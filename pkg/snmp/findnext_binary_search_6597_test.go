package snmp

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// #6597: the GETNEXT successor lookup must not be linear in the MIB size.
//
// `findNextOIDSnap` resolved each lexicographic successor by scanning the whole
// MIB view — O(static + interfaces x columns) PER VARBIND. Because the agent
// runs on a single serial goroutine, that per-lookup cost is the floor on
// requests/second for every operation at once, and it grows with interface
// count: a max-size plain GETNEXT of 239 deep ifXTable OIDs measured ~33 ms
// (~30 req/s for that shape) while fixing #6551.
//
// This is a PERFORMANCE change, so the binding obligation is that it does not
// alter results. `TestFindNextOIDMatchesLinearReference` is that binding: it
// runs the pre-fix algorithm as a reference and asserts byte-identical
// successors across an exhaustive probe set, rather than spot-checking a few
// OIDs.

// oidString renders an OID for test messages. Local to this file so the test
// does not depend on a production formatter that may not exist.
func oidString(o []int) string {
	if o == nil {
		return "<nil>"
	}
	parts := make([]string, len(o))
	for i, v := range o {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ".")
}

// linearFindNextReference is the PRE-FIX algorithm, verbatim in structure:
// scan staticOIDs, then ifTable column-major, then ifXTable column-major,
// returning the first candidate that sorts after oid. It is the oracle the new
// binary search must agree with.
func linearFindNextReference(oid []int, ifaces []IfData) []int {
	for _, candidate := range staticOIDs {
		if oidCompare(candidate, oid) > 0 {
			return candidate
		}
	}
	if len(ifaces) == 0 {
		return nil
	}
	for _, col := range ifTableColumns {
		for _, iface := range ifaces {
			candidate := make([]int, len(oidIfTablePrefix)+2)
			copy(candidate, oidIfTablePrefix)
			candidate[len(oidIfTablePrefix)] = col
			candidate[len(oidIfTablePrefix)+1] = iface.IfIndex
			if oidCompare(candidate, oid) > 0 {
				return candidate
			}
		}
	}
	for _, col := range ifXTableColumns {
		for _, iface := range ifaces {
			candidate := make([]int, len(oidIfXTablePrefix)+2)
			copy(candidate, oidIfXTablePrefix)
			candidate[len(oidIfXTablePrefix)] = col
			candidate[len(oidIfXTablePrefix)+1] = iface.IfIndex
			if oidCompare(candidate, oid) > 0 {
				return candidate
			}
		}
	}
	return nil
}

func ifDataAscending(n int) []IfData {
	out := make([]IfData, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, IfData{IfIndex: i, IfDescr: fmt.Sprintf("ge-0-0-%d", i)})
	}
	return out
}

func agentWithIfaces(ifaces []IfData) *Agent {
	a := &Agent{}
	a.SetIfDataFn(func() []IfData { return ifaces })
	return a
}

// probeOIDs returns an exhaustive probe set for a given MIB view: every OID in
// the view, each one MINUS the last sub-identifier and PLUS one, plus the
// boundary probes above and below every table. Walking from each of these
// exercises every branch the successor lookup can take.
func probeOIDs(view [][]int) [][]int {
	var probes [][]int
	add := func(o []int) { probes = append(probes, append([]int(nil), o...)) }
	for _, o := range view {
		add(o)
		if len(o) > 0 {
			lower := append([]int(nil), o...)
			lower[len(lower)-1]--
			add(lower)
			higher := append([]int(nil), o...)
			higher[len(higher)-1]++
			add(higher)
			add(o[:len(o)-1]) // the prefix, i.e. a bare column
		}
	}
	add([]int{})
	add([]int{1})
	add([]int{1, 3, 6, 1, 2, 1})
	add([]int{1, 3, 6, 1, 2, 1, 2, 2, 1})
	add([]int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1})
	add([]int{1, 3, 6, 1, 2, 1, 99})
	add([]int{2})
	return probes
}

// TestFindNextOIDMatchesLinearReference is the equivalence binding: for every
// probe, the binary search must return exactly what the linear scan returned.
func TestFindNextOIDMatchesLinearReference(t *testing.T) {
	for _, n := range []int{0, 1, 2, 5, 17} {
		t.Run(fmt.Sprintf("ifaces=%d", n), func(t *testing.T) {
			ifaces := ifDataAscending(n)
			a := agentWithIfaces(ifaces)
			snap := a.newIfSnapshot()
			view := snap.mibOIDs()

			probes := probeOIDs(view)
			if len(probes) == 0 {
				t.Fatal("probe set is empty — the test would pass vacuously")
			}
			for _, probe := range probes {
				got := a.findNextOIDSnap(probe, a.newIfSnapshot())
				want := linearFindNextReference(probe, ifaces)
				if oidString(got) != oidString(want) {
					t.Fatalf("successor of %s: got %s, want %s (linear reference)",
						oidString(probe), oidString(got), oidString(want))
				}
			}
			t.Logf("%d probes agreed with the linear reference", len(probes))
		})
	}
}

// TestFullWalkMatchesLinearReference walks the ENTIRE MIB from the root with
// both implementations and asserts the emitted sequences are identical. The
// probe test above checks each successor in isolation; this checks that
// chaining them produces the same walk, which is what a manager actually sees.
func TestFullWalkMatchesLinearReference(t *testing.T) {
	ifaces := ifDataAscending(7)
	a := agentWithIfaces(ifaces)

	walk := func(next func([]int) []int) []string {
		var out []string
		cur := []int{}
		for range 10000 {
			n := next(cur)
			if n == nil {
				return out
			}
			out = append(out, oidString(n))
			cur = n
		}
		t.Fatal("walk did not terminate")
		return nil
	}

	gotWalk := walk(func(o []int) []int { return a.findNextOIDSnap(o, a.newIfSnapshot()) })
	wantWalk := walk(func(o []int) []int { return linearFindNextReference(o, ifaces) })

	if len(gotWalk) != len(wantWalk) {
		t.Fatalf("walk length %d != reference %d", len(gotWalk), len(wantWalk))
	}
	if len(gotWalk) == 0 {
		t.Fatal("empty walk — the test would pass vacuously")
	}
	for i := range gotWalk {
		if gotWalk[i] != wantWalk[i] {
			t.Fatalf("walk diverges at %d: got %s, want %s", i, gotWalk[i], wantWalk[i])
		}
	}
	t.Logf("%d-OID walk is byte-identical to the linear reference", len(gotWalk))
}

// TestMIBOIDViewIsSorted pins the precondition the binary search REQUIRES.
// sort.Search on an unsorted slice returns silently wrong answers, so this is
// not a style assertion: it is the guard that keeps the lookup correct if a
// column list or table order is ever edited.
func TestMIBOIDViewIsSorted(t *testing.T) {
	snap := agentWithIfaces(ifDataAscending(9)).newIfSnapshot()
	view := snap.mibOIDs()
	if len(view) == 0 {
		t.Fatal("empty MIB view")
	}
	if !sort.SliceIsSorted(view, func(i, j int) bool { return oidCompare(view[i], view[j]) < 0 }) {
		for i := 1; i < len(view); i++ {
			if oidCompare(view[i-1], view[i]) >= 0 {
				t.Fatalf("MIB view is not sorted at %d: %s then %s — sort.Search "+
					"gives silently wrong successors on an unsorted slice",
					i, oidString(view[i-1]), oidString(view[i]))
			}
		}
	}
}

// TestUnsortedProviderWalksEveryRowInOrder pins the correctness IMPROVEMENT and
// is the one deterministic RED-on-revert in this file.
//
// The linear scan's lexicographic correctness silently depended on `ifDataFn`
// returning IfIndex-ascending data, and nothing enforces that — the production
// provider (`buildSNMPIfData`, pkg/daemon) appends in netlink LinkList order
// with no sort.
//
// The interesting part is HOW it failed. Given an out-of-order provider the old
// scan still emitted ASCENDING OIDs, because it returned the first candidate
// sorting after the cursor — but it SKIPPED every interface whose index sorted
// below one already emitted in that column. An ascending-only assertion
// therefore passes on the broken code; completeness is what discriminates. That
// is why this asserts the full expected set, not just the ordering.
//
// FAIL-ON-REVERT: restore the linear scan and this test reds with missing rows.
func TestUnsortedProviderWalksEveryRowInOrder(t *testing.T) {
	unsorted := []IfData{{IfIndex: 7}, {IfIndex: 2}, {IfIndex: 11}, {IfIndex: 1}}
	a := agentWithIfaces(unsorted)

	var walk [][]int
	cur := []int{}
	for range 10000 {
		n := a.findNextOIDSnap(cur, a.newIfSnapshot())
		if n == nil {
			break
		}
		walk = append(walk, n)
		cur = n
	}
	if len(walk) == 0 {
		t.Fatal("empty walk")
	}

	// Strictly ascending.
	for i := 1; i < len(walk); i++ {
		if oidCompare(walk[i-1], walk[i]) >= 0 {
			t.Fatalf("walk is not strictly ascending at %d: %s then %s — a "+
				"manager would loop (RFC 3416)",
				i, oidString(walk[i-1]), oidString(walk[i]))
		}
	}

	// ...AND complete. This is the assertion the old scan fails.
	want := map[string]bool{}
	for _, o := range staticOIDs {
		want[oidString(o)] = true
	}
	for _, tbl := range []struct {
		prefix []int
		cols   []int
	}{
		{oidIfTablePrefix, ifTableColumns},
		{oidIfXTablePrefix, ifXTableColumns},
	} {
		for _, col := range tbl.cols {
			for _, iface := range unsorted {
				o := append(append([]int(nil), tbl.prefix...), col, iface.IfIndex)
				want[oidString(o)] = true
			}
		}
	}
	got := map[string]bool{}
	for _, o := range walk {
		got[oidString(o)] = true
	}
	var missing []string
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		shown := missing
		if len(shown) > 6 {
			shown = shown[:6]
		}
		t.Fatalf("the walk SKIPPED %d of %d MIB rows given an out-of-order "+
			"provider (e.g. %v) — ascending but incomplete, so a manager "+
			"silently never sees those interfaces",
			len(missing), len(want), shown)
	}
}

// BenchmarkFindNextOIDByInterfaceCount pins per-lookup cost against interface
// count. A regression to the linear scan shows up as cost growing with the
// interface count instead of staying flat-ish (log).
func BenchmarkFindNextOIDByInterfaceCount(b *testing.B) {
	for _, n := range []int{1, 8, 64, 256} {
		b.Run(fmt.Sprintf("ifaces=%d", n), func(b *testing.B) {
			a := agentWithIfaces(ifDataAscending(n))
			snap := a.newIfSnapshot()
			_ = snap.mibOIDs() // build once, as a real PDU does
			// The worst case for the old scan: an OID near the END of the MIB,
			// so the linear walk traverses everything before finding it.
			view := snap.mibOIDs()
			probe := view[len(view)-2]
			b.ResetTimer()
			for range b.N {
				if got := a.findNextOIDSnap(probe, snap); got == nil {
					b.Fatal("no successor")
				}
			}
		})
	}
}
