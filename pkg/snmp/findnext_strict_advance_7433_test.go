package snmp

import (
	"testing"
	"time"
)

// #7433: `findNextV1OIDSnap` contains the one unbounded loop over the successor
// lookup, and it terminates ONLY because the successor STRICTLY ADVANCES past
// the cursor. Nothing asserted that.
//
// It was found by mutation, and by the worst kind: changing the search
// predicate from `> 0` to `>= 0` makes an OID its own successor and the walk
// never terminates. **The cell HUNG rather than failing.** A hang is worse than
// a failure — it produces no `--- FAIL` line, so a harness gating on named
// failures scores it as a VOID or, depending on how it counts, as an escape.
// The matrix had to be re-run under `-timeout` before it could be read at all.
//
// It is not a live defect. Two independent bounds hold at HEAD, and both are
// incidental rather than asserted: GETNEXT performs one lookup per request OID
// with no loop over the successor, and GETBULK is bounded by max-repetitions
// plus the #6551 byte budget. So a spin is not reachable from the wire today.
//
// The concern is that the loop's termination rests on a property of a DIFFERENT
// function, and neither the property nor the dependency was written down or
// tested. Two things go wrong at once when that is true: someone optimises
// `findNextOIDSnap` and cannot see what depends on it, and the failure they
// cause is a hang rather than a red.

// withDeadline7433 runs fn on its own goroutine and fails the test if it does
// not return in time.
//
// EVERY cell here that CALLS the loop must go through this. The first draft did
// not, and the mutation matrix caught it: removing `cur = next` from
// findNextV1OIDSnap makes a SINGLE call spin forever, so a cell that calls it
// on the test goroutine hangs the whole package — no `--- FAIL` line, no
// attribution, just a suite that never returns. That is precisely the failure
// mode this issue exists to convert into a red, and the test written to convert
// it reproduced it instead.
//
// The deadline is a liveness bound, not a timing assertion. Its value carries
// no meaning and raising it weakens nothing: a correct walk finishes in
// microseconds.
func withDeadline7433(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not terminate. findNextV1OIDSnap loops until the successor "+
			"lookup returns nil, so a successor that does not strictly advance — or a "+
			"loop body that fails to advance the cursor — spins forever (#7433). This "+
			"deadline exists so that failure is a RED line rather than a hung suite "+
			"with no attribution", what)
	}
}

// TestSuccessorStrictlyAdvances7433 states the property directly, on the
// function that owns it, over the whole view.
//
// Not "the walk terminates" — that is the CONSEQUENCE, and asserting it
// requires running the walk, which is exactly the thing that hangs when the
// property breaks. Asserting the property itself fails in microseconds.
func TestSuccessorStrictlyAdvances7433(t *testing.T) {
	a := agentWithIfaces(ifDataAscending(6))
	view := a.newIfSnapshot().mibOIDs()
	if len(view) == 0 {
		t.Fatal("the MIB view is empty, so nothing below is exercised")
	}

	for _, probe := range probeOIDs(view) {
		next := a.findNextOIDSnap(probe, a.newIfSnapshot())
		if next == nil {
			continue // end of view is a legitimate answer
		}
		if cmp := oidCompare(next, probe); cmp <= 0 {
			t.Fatalf("findNextOIDSnap(%v) = %v, which sorts %s the cursor "+
				"(oidCompare = %d). findNextV1OIDSnap's loop advances by assigning "+
				"cur = next, so a successor that does not STRICTLY advance makes it "+
				"spin forever — and a spin is a hang, not a failure (#7433)",
				probe, next, map[bool]string{true: "BEFORE", false: "EQUAL TO"}[cmp < 0], cmp)
		}
	}
}

// The same property from the loop's own side, with a hard deadline so a
// regression FAILS instead of hanging the package.
//
// The deadline is not a timing assertion and its value carries no meaning — it
// is generous by two orders of magnitude for a view this size. It exists so
// that the failure mode of a broken invariant is a red line naming this issue,
// rather than a suite that never returns and a CI job killed with no attribution.
func TestV1WalkTerminates7433(t *testing.T) {
	a := agentWithIfaces(ifDataAscending(6))
	view := a.newIfSnapshot().mibOIDs()

	steps := 0
	withDeadline7433(t, "the v1 walk", func() {
		cur := []int(nil)
		for {
			next, _, _ := a.findNextV1OIDSnap(cur, a.newIfSnapshot())
			if next == nil {
				return
			}
			steps++
			if steps > len(view)+16 {
				// Bounded so a broken invariant cannot allocate forever before
				// the deadline fires.
				return
			}
			cur = next
		}
	})
	if steps == 0 {
		t.Fatal("the v1 walk returned nothing at all; the cells here assert " +
			"termination, and a walk that never starts satisfies that vacuously")
	}
	if steps > len(view) {
		t.Errorf("the v1 walk took %d steps over a %d-OID view. It can only revisit "+
			"an OID if the successor failed to strictly advance (#7433)", steps, len(view))
	}
}

// The NEGATIVE CONTROL for the deadline cell: a Counter64 node must still be
// stepped OVER, not treated as the end of the view. Without this, both cells
// above are satisfied by a v1 walk that returns nil immediately — termination
// would be trivially true and the skip behaviour the function exists for would
// be unbound.
func TestV1WalkStepsOverCounter64_7433(t *testing.T) {
	a := agentWithIfaces(ifDataAscending(4))
	snap := a.newIfSnapshot()

	var sawCounter64 bool
	for _, oid := range snap.mibOIDs() {
		if _, tag := a.getOIDValueSnap(oid, snap); tag == tagCounter64 {
			sawCounter64 = true
			break
		}
	}
	if !sawCounter64 {
		t.Skip("this MIB view serves no Counter64 node, so there is nothing for " +
			"the v1 skip to step over")
	}

	seen := 0
	var badTag []int
	withDeadline7433(t, "the v1 Counter64-skip walk", func() {
		cur := []int(nil)
		for i := 0; i < len(snap.mibOIDs())+16; i++ {
			next, _, tag := a.findNextV1OIDSnap(cur, a.newIfSnapshot())
			if next == nil {
				return
			}
			if tag == tagCounter64 {
				badTag = next
				return
			}
			seen++
			cur = next
		}
	})
	if badTag != nil {
		t.Fatalf("the v1 walk returned a Counter64 node at %v; RFC 2089 says v1 "+
			"cannot carry it and findNextV1OIDSnap exists to skip it", badTag)
	}
	if seen == 0 {
		t.Fatal("the v1 walk visited nothing, so the skip assertion above is vacuous")
	}
}

// THE BOUND ITSELF. With the real successor lookup the step bound is
// unreachable — the successor is correct, so the loop always terminates on its
// own and a mutation deleting the bound escapes every other cell here
// (measured: it did).
//
// A guard whose failure mode is a HANG is the one most worth binding, so this
// supplies a successor that never advances and asserts the loop still returns.
// The production path is untouched: `findNextV1OIDSnap` passes
// `a.findNextOIDSnap` and there is one caller.
func TestV1WalkIsBoundedAgainstANonAdvancingSuccessor7433(t *testing.T) {
	a := agentWithIfaces(ifDataAscending(4))
	snap := a.newIfSnapshot()
	view := snap.mibOIDs()
	if len(view) == 0 {
		t.Fatal("empty MIB view")
	}

	// THE FIXTURE MUST REACH THE SKIP BRANCH, and the first version did not.
	//
	// It returned view[0], whose value is an ordinary (non-Counter64) type — so
	// the loop returned on its FIRST iteration and the non-advancing cursor
	// never mattered. Both the delete-the-bound and widen-the-bound mutations
	// escaped, because the loop body executed once either way.
	//
	// The spin needs the `continue` arm: a Counter64 value makes the loop set
	// `cur = next` and go round again. So the stuck successor has to name a
	// Counter64 OID.
	var c64 []int
	for _, oid := range view {
		if _, tag := a.getOIDValueSnap(oid, snap); tag == tagCounter64 {
			c64 = oid
			break
		}
	}
	if c64 == nil {
		t.Skip("this MIB view serves no Counter64 node, so the v1 skip branch — " +
			"the only arm that loops — cannot be reached")
	}

	// Every OID is its own successor: the cursor never moves, and because the
	// value is Counter64 the loop keeps skipping. That is the spin.
	calls := 0
	stuck := func(_ []int, _ *ifSnapshot) []int {
		calls++
		return c64
	}

	withDeadline7433(t, "the v1 walk against a non-advancing successor", func() {
		a.findNextV1OIDSnapWith(nil, snap, stuck)
	})

	if calls == 0 {
		t.Fatal("the successor was never consulted; the walk did not run and the " +
			"assertion below is vacuous")
	}
	if calls < 2 {
		t.Fatalf("the successor was consulted %d time(s); the loop returned before "+
			"iterating, so the step bound was never the thing that stopped it and "+
			"this cell proves nothing about it", calls)
	}
	if calls > len(view)+3 {
		t.Errorf("the walk made %d successor calls over a %d-OID view; the step "+
			"bound must stop it at the view length (#7433)", calls, len(view))
	}
}
