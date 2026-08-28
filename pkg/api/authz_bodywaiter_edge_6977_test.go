package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// authz_bodywaiter_edge_6977_test.go — #6977 class A.
//
// The mutation gate's "a request is parked reading its caller's body" counter is
// PROCESS-GLOBAL: every api.Server in the process adds to it. The wait helper
// used to accept any value above zero, so a park the calling case did not create
// satisfied its edge and the case proceeded before its own request had reached
// the gate. Two shapes produce that:
//
//   - a case that returns with a request still parked, and the next case (under
//     -shuffle, not necessarily the next one in the source) takes it for its own;
//   - a case that parks TWICE, where the second wait is met by the first park.
//     parkFlood in authz_bodybudget_customclass_6954_test.go does exactly this.
//
// Every call site avoided the first by calling waitForGateQuiescent beforehand.
// That works and is not what this cell is about: it is a convention living in a
// different statement — sometimes a different function — from the wait that
// depends on it. The delta form is attributable by construction, because a
// leftover park raises the baseline too.
//
// WHAT MAKES THIS CELL NON-VACUOUS. The fixture must contain a park the wait
// under test did not create, and that must be MEASURED, not assumed: if the
// foreign park never happened, "the wait did not return" would be true for the
// wrong reason and the cell would pass against a broken helper. FOREIGN_PARK_IS_
// PRESENT is that control — it asserts the old `> 0` predicate IS satisfied by
// the same fixture, so the two predicates are being compared on identical state
// and the only difference is the baseline.

// TestBodyWaiterEdgeIsTheCallersOwn_6977 is the paired cell: the delta must be
// necessary (a foreign park does not satisfy it) AND sufficient (the caller's
// own park does).
func TestBodyWaiterEdgeIsTheCallersOwn_6977(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: fixedPeerUID(authzUIDSuperuser),
	})
	// Start from a known level so the numbers below are readable; the property
	// under test does NOT depend on it, which is the whole point.
	waitForGateQuiescent(t)

	// The FOREIGN park: one request parked on a body it never finishes sending.
	// It stands in for whatever else in the process is holding the counter up —
	// a previous case's leftover, or this case's own earlier park.
	const body = `{"input":"set system host-name r6977"}`
	foreign := openDeclaredBody(t, base, "POST /api/v1/config/set", len(body), "", nil)
	_ = foreign
	if !awaitMutationBodyWaiterAbove(0, 10*time.Second) {
		t.Fatal("the fixture never parked its foreign request, so every assertion below " +
			"would be measuring an empty gate rather than a contended one")
	}
	baseline := MutationBodyWaitersForTest()
	if baseline < 1 {
		t.Fatalf("baseline is %d after a request parked; the counter is not reporting the "+
			"state this cell is built on", baseline)
	}

	// CONTROL: the predicate this replaced — "some request is parked" — IS
	// satisfied by that foreign park. Without this the next assertion could hold
	// because nothing is parked at all, and the cell would prove nothing about
	// attribution.
	if !awaitMutationBodyWaiterAbove(0, time.Second) {
		t.Fatal("FOREIGN_PARK_IS_PRESENT: the old `> 0` predicate is NOT satisfied by the " +
			"fixture, so the two predicates are not being compared on the same state and " +
			"the necessity assertion below is vacuous")
	}

	// NECESSARY: with the baseline taken AFTER the foreign park, that park must
	// not satisfy the wait. This is the defect: with `> 0` this returns
	// immediately and the caller proceeds before its own request exists.
	if awaitMutationBodyWaiterAbove(baseline, 300*time.Millisecond) {
		t.Fatalf("the wait returned on a park the caller did not create (baseline %d, now %d). "+
			"A case whose edge can be satisfied by another request has no edge — it has a "+
			"coincidence with a good success rate, and it proceeds to read gate state before "+
			"its own request has reached the gate (#6977)",
			baseline, MutationBodyWaitersForTest())
	}

	// SUFFICIENT: the caller's OWN park does satisfy it. Without this half, the
	// necessity assertion is satisfied by a predicate that never returns true.
	own := openDeclaredBody(t, base, "POST /api/v1/config/set", len(body), "", nil)
	_ = own
	if !awaitMutationBodyWaiterAbove(baseline, 10*time.Second) {
		t.Fatalf("the caller's own park never satisfied the wait (baseline %d, now %d) — the "+
			"delta form must still be an edge, not merely a stricter predicate that never "+
			"fires", baseline, MutationBodyWaitersForTest())
	}
}

// TestBodyAbsenceAssertionIsADeltaToo_6977 covers the OTHER direction of the
// same contamination.
//
// TestNoBodyRouteIsNotBufferedByTheGate_5561 asserts an ABSENCE on the same
// process-global counter — "no request is parked after a no-body route
// answered" — and that is its PROPERTY, not a precondition. So a foreign park
// does not make it pass early; it makes it RED, accusing a route that parked
// nothing. `count == baseline` says what the sentence means ("this route added
// no park") and survives a park it did not create; `count == 0` does not.
//
// Deterministic in both directions because the fixture manufactures the foreign
// park rather than waiting for one.
func TestBodyAbsenceAssertionIsADeltaToo_6977(t *testing.T) {
	usePasswdFixture(t)
	_, base := authzServer(t, Config{
		Addr:         "127.0.0.1:8080",
		Store:        authzStore(t, authzTestConfig),
		PeerLookupFn: fixedPeerUID(authzUIDSuperuser),
	})
	waitForGateQuiescent(t)

	const body = `{"input":"set system host-name r6977b"}`
	foreign := openDeclaredBody(t, base, "POST /api/v1/config/set", len(body), "", nil)
	_ = foreign
	if !awaitMutationBodyWaiterAbove(0, 10*time.Second) {
		t.Fatal("the fixture never parked its foreign request, so both predicates below are " +
			"being compared on an empty gate and neither means anything")
	}
	baseline := MutationBodyWaitersForTest()

	// The absence a no-body route asserts: nothing NEW parked. The route is not
	// driven here — what is under test is which predicate expresses it.
	if got := MutationBodyWaitersForTest(); got != baseline {
		t.Fatalf("the delta predicate is unstable on its own fixture: %d != %d", got, baseline)
	}
	// CONTROL: the literal-zero form this replaced would red on the same state,
	// naming a route that parked nothing. Without this the assertion above could
	// hold because the gate is empty, and the cell would prove nothing.
	if baseline == 0 {
		t.Fatal("ZERO_FORM_WOULD_RED: the fixture holds no foreign park, so `count == 0` and " +
			"`count == baseline` are the same predicate here and this cell is vacuous")
	}
}

// TestBodyWaiterHelperIsNotUsedUnattributably_6977 binds the WIRING: the
// unattributable helper must not come back, and the delta helper must actually
// be the idiom the package uses.
//
// The behavioural cell above tests the helper. It cannot see a call site that
// goes back to asking "is anything parked at all" — and that is the shape the
// defect takes, because the unattributable form is the one that is easier to
// write. Parsed with parser.ParseFile(..., 0), so comments are discarded before
// matching: the prose in these files that QUOTES the old predicate cannot
// satisfy it.
func TestBodyWaiterHelperIsNotUsedUnattributably_6977(t *testing.T) {
	idents := testFileIdents6977(t)
	if len(idents) < 3 {
		t.Fatalf("parsed only %d distinct identifiers from the package's test files; this "+
			"guard is not reading the files it claims to audit", len(idents))
	}
	if files := idents["waitForMutationBodyWaiter"]; len(files) > 0 {
		t.Fatalf("waitForMutationBodyWaiter is back (%v). Its predicate was `parked > 0` with "+
			"no baseline, so a request the calling case did not open satisfied its wait. Use "+
			"waitForNewMutationBodyWaiter(t, baselineReadBeforeYourOwnRequest) (#6977)", files)
	}
	users := idents["waitForNewMutationBodyWaiter"]
	// The helper's own file always counts itself; a second file is what shows it
	// is the idiom the package uses rather than a definition nothing calls.
	if len(users) < 2 {
		t.Fatalf("waitForNewMutationBodyWaiter appears in %v — fewer than two files. Either "+
			"the call sites stopped using it, or they went back to a wait with no baseline, "+
			"which is the defect (#6977)", users)
	}
}

// testFileIdents6977 maps every identifier used in the package's _test.go files
// to the set of files using it. Comments are discarded by the parser, so prose
// cannot satisfy a lookup.
func testFileIdents6977(t *testing.T) map[string][]string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(self)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	out := map[string]map[string]bool{}
	files := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			if id, isIdent := n.(*ast.Ident); isIdent {
				if out[id.Name] == nil {
					out[id.Name] = map[string]bool{}
				}
				out[id.Name][name] = true
			}
			return true
		})
	}
	if files == 0 {
		t.Fatalf("found no _test.go files under %s; this guard would pass vacuously", dir)
	}
	res := map[string][]string{}
	for ident, fs := range out {
		names := make([]string, 0, len(fs))
		for n := range fs {
			names = append(names, n)
		}
		sort.Strings(names)
		res[ident] = names
	}
	return res
}
