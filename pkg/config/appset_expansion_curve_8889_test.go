package config

import (
	"fmt"
	"testing"
)

// Issue 8889: nested application-set expansion was quartic and re-ran for every
// referencing policy, under the store's READ lock in CommitCheck -- so Commit,
// Load and the HA SyncApply path queued behind it.
//
// The depth cap of 3 is what makes the exponent knowable, and it is NOT the
// defect: it is a working guard, and removing or raising it turns a bounded
// cost into an unbounded one. It stays, and a cell below asserts it still
// fires.
//
// THE ASSERTION IS ON THE CURVE, NOT A STOPWATCH. A wall-clock threshold is
// flaky under load and tells the next reader nothing about why the number is
// what it is. These cells count expansion BODIES: memoized, the count must grow
// LINEARLY in the number of sets (at most one body per (set, depth) pair, and
// depth is capped at 4 values). Unmemoized it grows as B^4, and the failure
// text prints both curves.

// buildNestedAppSets8889 builds `breadth` sets at each of 4 tiers, each tier-n
// set referencing every tier-(n+1) set, with the leaf tier referencing real
// applications. That is the shape whose shared subtrees get re-expanded.
func buildNestedAppSets8889(breadth int) *ApplicationsConfig {
	apps := &ApplicationsConfig{
		Applications:    map[string]*Application{},
		ApplicationSets: map[string]*ApplicationSet{},
	}
	for i := 0; i < breadth; i++ {
		name := fmt.Sprintf("xpfapp%d", i)
		apps.Applications[name] = &Application{Name: name, Protocol: "tcp", DestinationPort: "80"}
	}
	// Leaf tier: sets of real applications.
	for i := 0; i < breadth; i++ {
		members := make([]string, 0, breadth)
		for j := 0; j < breadth; j++ {
			members = append(members, fmt.Sprintf("xpfapp%d", j))
		}
		name := fmt.Sprintf("xpfset3_%d", i)
		apps.ApplicationSets[name] = &ApplicationSet{Name: name, Applications: members}
	}
	// Tiers 2, 1, 0: each set references every set of the tier below.
	for tier := 2; tier >= 0; tier-- {
		for i := 0; i < breadth; i++ {
			members := make([]string, 0, breadth)
			for j := 0; j < breadth; j++ {
				members = append(members, fmt.Sprintf("xpfset%d_%d", tier+1, j))
			}
			name := fmt.Sprintf("xpfset%d_%d", tier, i)
			apps.ApplicationSets[name] = &ApplicationSet{Name: name, Applications: members}
		}
	}
	return apps
}

// naiveExpansionCount8889 mirrors the pre-fix recursion WITHOUT a memo, so the
// guard can print the curve it replaced instead of asserting against a
// remembered number.
func naiveExpansionCount8889(name string, apps *ApplicationsConfig, depth int) int {
	if depth > 3 {
		return 1
	}
	as, ok := lookupApplicationSet(name, apps.ApplicationSets)
	if !ok {
		return 1
	}
	n := 1
	for _, m := range as.Applications {
		if memberIsNestedSet(m, apps) {
			n += naiveExpansionCount8889(m, apps, depth+1)
		}
	}
	return n
}

func TestAppSetExpansionIsLinearNotQuartic8889(t *testing.T) {
	type row struct {
		breadth, sets, memoCalls, naive, members int
	}
	var rows []row
	for _, b := range []int{4, 8, 16} {
		apps := buildNestedAppSets8889(b)
		memo := newAppSetMemo()
		got, err := expandAppSetMemo("xpfset0_0", apps, 0, memo)
		if err != nil {
			t.Fatalf("breadth %d: expansion failed: %v", b, err)
		}
		// LIVENESS: the fixture must actually reach expandAppSet and produce
		// members. A fixture that expands to nothing makes every count
		// assertion below vacuous.
		if memo.calls == 0 || len(got) == 0 {
			t.Fatalf("breadth %d: fixture did not exercise expansion (calls=%d members=%d)",
				b, memo.calls, len(got))
		}
		rows = append(rows, row{b, len(apps.ApplicationSets), memo.calls,
			naiveExpansionCount8889("xpfset0_0", apps, 0), len(got)})
	}

	for _, r := range rows {
		t.Logf("breadth=%2d sets=%3d memoised-bodies=%4d naive-bodies=%8d members=%d",
			r.breadth, r.sets, r.memoCalls, r.naive, r.members)
	}

	// THE CURVE. At most one body per (set, depth) pair, and depth takes at
	// most 4 values, so the memoised count is bounded by 4 x sets -- linear.
	// The naive count is quartic in breadth and blows through this bound.
	for _, r := range rows {
		if limit := 4 * r.sets; r.memoCalls > limit {
			t.Errorf("breadth %d: %d expansion bodies for %d sets, bound is %d (4 per (set,depth)). "+
				"The memo is not collapsing shared subtrees; naive would be %d",
				r.breadth, r.memoCalls, r.sets, limit, r.naive)
		}
	}

	// And the ratio must not grow with breadth: quartic growth shows up here
	// even if the absolute bound above were loosened.
	first, last := rows[0], rows[len(rows)-1]
	fr := float64(first.memoCalls) / float64(first.sets)
	lr := float64(last.memoCalls) / float64(last.sets)
	if lr > fr*1.5 {
		t.Errorf("bodies-per-set grew from %.2f (breadth %d) to %.2f (breadth %d) — "+
			"the cost is still super-linear in breadth", fr, first.breadth, lr, last.breadth)
	}
}

// CORRECTNESS BEFORE SPEED: a memo keyed wrongly returns the wrong set fast.
// The memoised expansion must equal an expansion performed with a FRESH memo
// per call (i.e. no cross-call reuse at all), by content and order.
func TestMemoisedExpansionMatchesUncached8889(t *testing.T) {
	apps := buildNestedAppSets8889(6)
	shared := newAppSetMemo()
	for _, name := range []string{"xpfset0_0", "xpfset1_2", "xpfset2_3", "xpfset3_1", "xpfset0_0"} {
		viaShared, errS := expandAppSetMemo(name, apps, 0, shared)
		viaFresh, errF := expandAppSetMemo(name, apps, 0, newAppSetMemo())
		if (errS == nil) != (errF == nil) {
			t.Fatalf("%s: shared err=%v fresh err=%v", name, errS, errF)
		}
		if len(viaShared) == 0 {
			t.Fatalf("%s expanded to nothing — this comparison would be vacuous", name)
		}
		if len(viaShared) != len(viaFresh) {
			t.Fatalf("%s: shared memo produced %d members, fresh produced %d",
				name, len(viaShared), len(viaFresh))
		}
		for i := range viaShared {
			if viaShared[i] != viaFresh[i] {
				t.Errorf("%s member %d: shared %q, fresh %q", name, i, viaShared[i], viaFresh[i])
			}
		}
	}
}

// THE DEPTH CAP MUST STILL FIRE. Memoising must not accidentally satisfy the
// depth check — a name-keyed memo would serve a shallow success into a deep
// context and do exactly that, which is why the key carries the depth.
func TestDepthCapStillRejects8889(t *testing.T) {
	apps := &ApplicationsConfig{
		Applications:    map[string]*Application{"xpfapp": {Name: "xpfapp", Protocol: "tcp", DestinationPort: "80"}},
		ApplicationSets: map[string]*ApplicationSet{},
	}
	// A 5-deep chain: s0 -> s1 -> s2 -> s3 -> s4 -> app. Exceeds the max of 3.
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("xpfdeep%d", i)
		member := fmt.Sprintf("xpfdeep%d", i+1)
		if i == 4 {
			member = "xpfapp"
		}
		apps.ApplicationSets[name] = &ApplicationSet{Name: name, Applications: []string{member}}
	}
	memo := newAppSetMemo()
	if _, err := expandAppSetMemo("xpfdeep0", apps, 0, memo); err == nil {
		t.Fatal("a 5-deep nest was accepted — the depth cap is what makes the cost bounded, " +
			"and memoisation must not satisfy it")
	}
	// The same memo, reused: a cached deep failure must not become a success,
	// and a cached shallow success must not license a deeper reuse.
	if _, err := expandAppSetMemo("xpfdeep0", apps, 0, memo); err == nil {
		t.Fatal("the cap stopped firing on the second call through a warm memo")
	}
	if _, err := expandAppSetMemo("xpfdeep1", apps, 3, memo); err == nil {
		t.Fatal("a set that expands cleanly at depth 0 was accepted at depth 3 through the memo — " +
			"the memo key must carry the depth")
	}
}
