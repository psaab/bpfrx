package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// listener_retiredauth_classify_6993_test.go — #6993 / #7667.
//
// The flake's failing assertion IS identified: #7667 recorded it verbatim as
// the round-7 revocation property. What #6993 asks for beyond that is the
// classification — a property assertion and a precondition mean opposite
// things, and the test name describes only the first.
//
// The mechanism #7667 names is that a retired leg which finishes draining
// before ReplaceAuth is pruned from the retiring list and never tightened, so
// secret-a survives for a reason that has nothing to do with revocation. #7667
// made that impossible by holding a request in flight, and added a !drained
// precondition. Probing at master showed a residual in each half:
//
//   - the precondition samples `drained` at ONE instant, and the window that
//     matters runs from there to ReplaceAuth. Forcing drained=true immediately
//     before ReplaceAuth — the probe #7667 says reproduces the observed failure
//     exactly — still failed at the round-7 assertion, not the precondition;
//   - the hold waited 50ms after WRITING the request rather than for the
//     handler to have been entered. http.Server.Shutdown waits for requests it
//     has already dispatched; one that is written but not yet dispatched is not
//     among them.
//
// The two cells here bind the two halves. Neither half can be bound by
// observing a real drain: the hold exists to stop it happening, so a
// behavioural probe would have to defeat the fix to exercise it.

// TestRetiredRevocationFailureIsClassified_6993 binds the classification
// directly, which is why it was extracted into a function.
//
// Both rows matter. drained==true must NOT accuse the revocation path — that is
// the misreport the whole issue is about. drained==false must still accuse it —
// without that row, "never say revocation" passes, and the round-7 property
// would have no failure message of its own left.
func TestRetiredRevocationFailureIsClassified_6993(t *testing.T) {
	drainedMsg := retiredRevocationFailure6993(true)
	liveMsg := retiredRevocationFailure6993(false)

	if drainedMsg == liveMsg {
		t.Fatal("the two cases produce the SAME message, so the failure cannot be classified " +
			"at all — which is the state #6993 was filed about (#6993)")
	}
	// A drain that won is a fixture race. The message must say so, and must not
	// name the security property.
	if !strings.Contains(drainedMsg, "FIXTURE losing a race") {
		t.Fatalf("a drained leg reports %q, which does not name the fixture race. The "+
			"failure then reads as a revocation defect and the obvious remedy is to relax "+
			"the assertion — leaving a test that passes forever while guarding nothing "+
			"(#6993)", drainedMsg)
	}
	if strings.Contains(drainedMsg, "must still honour a revocation") {
		t.Fatalf("a drained leg reports the round-7 revocation message (%q). A leg the "+
			"server has already reaped is deliberately no longer maintained, so that "+
			"message accuses a property that is not broken (#6993/#7667)", drainedMsg)
	}
	// A leg that is genuinely still retiring is the case round 7 promises.
	if !strings.Contains(liveMsg, "must still honour a revocation") {
		t.Fatalf("a leg that is STILL RETIRING reports %q, which no longer names the "+
			"round-7 property. The classification must not be bought by deleting the "+
			"assertion it classifies (#5561 round 7)", liveMsg)
	}
}

// TestHeldRequestWaitsForHandlerEntry_6993 binds the second half.
//
// STRUCTURAL, and stated as such. Reverting the hold to a sleep is not
// deterministically observable: 50ms is usually enough for the server to accept
// and dispatch, so a behavioural cell would red only under load — and a cell
// that reds only sometimes is not a guard, it is a second flake. What CAN be
// asserted exactly is that the helper waits for the handler-entry signal and
// does not sleep instead.
//
// Parsed with parser.ParseFile(..., 0), so comments are discarded: the
// commentary in that file explaining why the sleep was wrong cannot satisfy it.
func TestHeldRequestWaitsForHandlerEntry_6993(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	path := filepath.Join(filepath.Dir(self), "listener_retiredauth_5561_test.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var found, sleeps, waitsOnEntered bool
	for _, d := range f.Decls {
		fd, isFunc := d.(*ast.FuncDecl)
		if !isFunc || fd.Body == nil || fd.Name.Name != "startHeldRequest7667" {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				if pkg, isIdent := v.X.(*ast.Ident); isIdent && pkg.Name == "time" && v.Sel.Name == "Sleep" {
					sleeps = true
				}
			case *ast.UnaryExpr:
				if v.Op != token.ARROW {
					return true
				}
				if id, isIdent := v.X.(*ast.Ident); isIdent && id.Name == "entered" {
					waitsOnEntered = true
				}
			}
			return true
		})
	}

	if !found {
		t.Fatal("startHeldRequest7667 is gone from listener_retiredauth_5561_test.go; this " +
			"guard is not reading the helper it claims to audit")
	}
	if !waitsOnEntered {
		t.Fatal("startHeldRequest7667 no longer waits on the handler-entry signal. " +
			"http.Server.Shutdown waits for requests it has already DISPATCHED, so a " +
			"request that has been written but not yet dispatched does not stop the drain — " +
			"and a drain that lands after the !drained precondition is reported as a " +
			"revocation defect (#6993/#7667)")
	}
	if sleeps {
		t.Fatal("startHeldRequest7667 sleeps. A sleep is not the edge: it narrows the window " +
			"in which the leg can still drain rather than closing it, and when it loses, the " +
			"failure names a security property that is not broken (#6993/#7667)")
	}
}
