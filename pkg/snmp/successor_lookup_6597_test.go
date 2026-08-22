package snmp

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// #6597: findNextOIDSnap resolved each lexicographic successor by scanning the
// whole MIB, so a walk was quadratic in the number of served OIDs (static +
// 20*interfaces). It is now a binary search over a virtual sorted array.
//
// This is a PERFORMANCE change, so the tests here are in two halves: one half
// proves the answers did not move, the other proves the cost did.

// ifacesFor6597 returns n interfaces with ascending IfIndex, the shape
// getIfData guarantees.
// oidStr6597 renders an OID for comparison and failure messages. nil (no
// successor) renders distinctly from the empty OID so the two cannot be
// confused in an equality check.
func oidStr6597(oid []int) string {
	if oid == nil {
		return "<none>"
	}
	parts := make([]string, len(oid))
	for i, v := range oid {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ".")
}

func ifacesFor6597(n int) []IfData {
	out := make([]IfData, n)
	for i := range out {
		out[i] = IfData{
			IfIndex: i + 1,
			IfDescr: fmt.Sprintf("ge-0-0-%d", i),
			IfName:  fmt.Sprintf("ge-0-0-%d", i),
			IfType:  6, IfMtu: 1500, IfSpeed: 1_000_000_000,
			AdminStatus: 1, OperStatus: 1, IfHighSpeed: 1000,
		}
	}
	return out
}

func agentFor6597(ifaces []IfData) *Agent {
	a := &Agent{}
	a.ifDataFn = func() []IfData { return ifaces }
	return a
}

// findNextOIDLinear6597 is the pre-#6597 implementation, preserved VERBATIM as
// the equivalence oracle. If the binary search and this disagree on any OID,
// the optimisation changed an answer and the change is wrong.
func findNextOIDLinear6597(oid []int, ifaces []IfData) []int {
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

// probeOIDs6597 returns the OIDs to compare the two implementations over: every
// OID an actual walk visits, plus off-tree probes a manager can legitimately
// send -- truncated prefixes, unserved columns, out-of-range ifIndexes, and
// OIDs longer than any entry (a manager resuming from a leaf it appended to).
func probeOIDs6597(ifaces []IfData) [][]int {
	probes := [][]int{
		{1}, {1, 3}, {1, 3, 6, 1},
		{1, 3, 6, 1, 2, 1, 1},
		{1, 3, 6, 1, 2, 1, 2},
		{1, 3, 6, 1, 2, 1, 2, 2},
		{1, 3, 6, 1, 2, 1, 2, 2, 1},
		{1, 3, 6, 1, 2, 1, 31},
		{1, 3, 6, 1, 2, 1, 31, 1, 1, 1},
		{1, 3, 6, 1, 2, 1, 99},
		{1, 3, 6, 1, 4, 1, 1},
		{2},
	}
	// Unserved columns: 6 and 9 are absent from ifTableColumns, 8 and 9 from
	// ifXTableColumns. A GETNEXT landing on a hole must skip to the next
	// served column, and the two implementations must agree on where.
	for _, col := range []int{0, 6, 9, 16, 17, 99} {
		probes = append(probes,
			append(append([]int{}, oidIfTablePrefix...), col),
			append(append([]int{}, oidIfXTablePrefix...), col))
	}
	// Every real entry, plus each entry's neighbours in index space.
	for _, spec := range []struct {
		prefix []int
		cols   []int
	}{{oidIfTablePrefix, ifTableColumns}, {oidIfXTablePrefix, ifXTableColumns}} {
		for _, col := range spec.cols {
			for _, idx := range []int{0, 1, len(ifaces), len(ifaces) + 1, 1 << 20} {
				probes = append(probes,
					append(append([]int{}, spec.prefix...), col, idx),
					append(append([]int{}, spec.prefix...), col, idx, 0))
			}
			for _, iface := range ifaces {
				probes = append(probes,
					append(append([]int{}, spec.prefix...), col, iface.IfIndex))
			}
		}
	}
	for _, static := range staticOIDs {
		probes = append(probes, static, append(append([]int{}, static...), 0))
	}
	return probes
}

func TestFindNextOIDSnapMatchesLinearScan_6597(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 8, 17} {
		t.Run(fmt.Sprintf("ifaces=%d", n), func(t *testing.T) {
			ifaces := ifacesFor6597(n)
			a := agentFor6597(ifaces)
			probes := probeOIDs6597(ifaces)
			if len(probes) == 0 {
				t.Fatal("probe set is empty; the comparison would be vacuous")
			}
			for _, probe := range probes {
				got := a.findNextOIDSnap(probe, a.newIfSnapshot())
				want := findNextOIDLinear6597(probe, ifaces)
				if oidStr6597(got) != oidStr6597(want) {
					t.Errorf("findNextOIDSnap(%s): got %s, pre-#6597 linear scan returned %s",
						oidStr6597(probe), oidStr6597(got), oidStr6597(want))
				}
			}
		})
	}
}

// TestWalkSequenceUnchanged_6597 compares the WALK, not just single lookups: a
// per-probe agreement could still permit a different traversal if the successor
// relation were subtly non-transitive.
func TestWalkSequenceUnchanged_6597(t *testing.T) {
	for _, n := range []int{1, 5, 12} {
		ifaces := ifacesFor6597(n)
		a := agentFor6597(ifaces)
		snap := a.newIfSnapshot()

		var got, want []string
		for cur := []int{1}; ; {
			nxt := a.findNextOIDSnap(cur, snap)
			if nxt == nil {
				break
			}
			got = append(got, oidStr6597(nxt))
			cur = nxt
		}
		for cur := []int{1}; ; {
			nxt := findNextOIDLinear6597(cur, ifaces)
			if nxt == nil {
				break
			}
			want = append(want, oidStr6597(nxt))
			cur = nxt
		}
		if wantLen := len(staticOIDs) + n*(len(ifTableColumns)+len(ifXTableColumns)); len(want) != wantLen {
			t.Fatalf("oracle walk visited %d OIDs, expected %d — the walk is not covering the MIB",
				len(want), wantLen)
		}
		if len(got) != len(want) {
			t.Fatalf("ifaces=%d: walk length %d, pre-#6597 walk length %d", n, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("ifaces=%d: walk diverges at %d: got %s, want %s", n, i, got[i], want[i])
			}
		}
	}
}

// TestSuccessorLookupIsNotLinear_6597 is the regression guard the issue asks
// for. It is deliberately NOT a timing assertion: it counts the allocations a
// worst-case lookup performs, which is deterministic and CI-stable.
//
// Every candidate OID the search examines is one allocation, so the count IS
// the number of MIB entries examined. Linear scans ~11*N candidates to reach
// the last ifXTable column; a binary search examines ~log2(11*N). At N=512 that
// is ~5600 versus ~14, so the two regimes are three orders of magnitude apart
// and no threshold in between is delicate.
func TestSuccessorLookupIsNotLinear_6597(t *testing.T) {
	const n = 512
	ifaces := ifacesFor6597(n)
	a := agentFor6597(ifaces)
	snap := a.newIfSnapshot()
	snap.get() // fault in the interface list so it is not charged to the lookup

	// The last served ifXTable column, last interface: the deepest OID in the
	// MIB, which a linear scan reaches only by examining every entry before it.
	deepest := append(append([]int{}, oidIfXTablePrefix...),
		ifXTableColumns[len(ifXTableColumns)-1], n)

	if got := a.findNextOIDSnap(deepest, snap); got != nil {
		t.Fatalf("expected the deepest OID to have no successor, got %s — the probe is "+
			"not landing at the end of the MIB and would not exercise a full linear scan",
			oidStr6597(got))
	}

	allocs := testing.AllocsPerRun(50, func() {
		a.findNextOIDSnap(deepest, snap)
	})

	linear := float64(len(ifXTableColumns) * n)
	const budget = 64 // ~14 expected; generous room for search-shape changes
	if allocs > budget {
		t.Errorf("worst-case successor lookup examined %.0f candidates over %d interfaces "+
			"(budget %d, pre-#6597 linear cost ~%.0f): the lookup has regressed toward a "+
			"linear MIB scan (#6597)", allocs, n, budget, linear)
	}
	if allocs >= linear {
		t.Errorf("lookup cost %.0f is at or above the full linear scan cost %.0f", allocs, linear)
	}
	t.Logf("worst-case lookup over %d interfaces: %.0f candidates examined (linear would be ~%.0f)",
		n, allocs, linear)
}

// TestGetIfDataSortsCallbackData_6597 binds the precondition the binary search
// rests on. getIfData's doc has always claimed sorted data while nothing
// sorted; buildSNMPIfData returns raw netlink.LinkList order. Unsorted, a
// linear scan emits a mis-ordered walk and a binary search emits an arbitrary
// one, so this is load-bearing rather than tidiness.
func TestGetIfDataSortsCallbackData_6597(t *testing.T) {
	unsorted := []IfData{
		{IfIndex: 9, IfDescr: "i9", IfName: "i9"},
		{IfIndex: 2, IfDescr: "i2", IfName: "i2"},
		{IfIndex: 40, IfDescr: "i40", IfName: "i40"},
		{IfIndex: 7, IfDescr: "i7", IfName: "i7"},
	}
	original := append([]IfData{}, unsorted...)
	a := agentFor6597(unsorted)

	got := a.getIfData()
	for i := 1; i < len(got); i++ {
		if got[i-1].IfIndex >= got[i].IfIndex {
			t.Fatalf("getIfData returned unsorted data: index %d (%d) not after %d",
				i, got[i].IfIndex, got[i-1].IfIndex)
		}
	}

	// The callback's slice must not be reordered underneath it.
	for i := range original {
		if unsorted[i].IfIndex != original[i].IfIndex {
			t.Errorf("getIfData mutated the callback's slice at %d: %d, was %d",
				i, unsorted[i].IfIndex, original[i].IfIndex)
		}
	}

	// And the resulting walk is strictly ascending, which is what RFC 3416
	// managers require and what unsorted data breaks.
	snap := a.newIfSnapshot()
	prev := []int{1}
	seen := 0
	for {
		nxt := a.findNextOIDSnap(prev, snap)
		if nxt == nil {
			break
		}
		if oidCompare(nxt, prev) <= 0 {
			t.Fatalf("walk went backwards: %s after %s", oidStr6597(nxt), oidStr6597(prev))
		}
		prev = nxt
		seen++
	}
	if want := len(staticOIDs) + len(unsorted)*(len(ifTableColumns)+len(ifXTableColumns)); seen != want {
		t.Errorf("walk emitted %d OIDs, expected %d", seen, want)
	}
}

// BenchmarkSuccessorLookup6597 pins per-lookup cost against interface count.
// Run with -benchmem; a linear regression shows as cost growing with N.
func BenchmarkSuccessorLookup6597(b *testing.B) {
	for _, n := range []int{8, 64, 512} {
		b.Run(fmt.Sprintf("ifaces=%d", n), func(b *testing.B) {
			a := agentFor6597(ifacesFor6597(n))
			snap := a.newIfSnapshot()
			snap.get()
			deepest := append(append([]int{}, oidIfXTablePrefix...),
				ifXTableColumns[len(ifXTableColumns)-1], n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.findNextOIDSnap(deepest, snap)
			}
		})
	}
}
