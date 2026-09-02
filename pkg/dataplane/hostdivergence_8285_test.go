package dataplane

import (
	"errors"
	"go/ast"
	"strings"
	"testing"
)

// abortErr drives the real post-mutation region the way production does, so the
// annotation under test is produced by the shipped contract rather than by a
// hand-call to annotateHostMutationOnAbort.
func abortErr(result *CompileResult, boom error) error {
	return runPostMutationSteps(result, func(*CompileResult) error { return boom })
}

// TestRetryAfterAbortStillReportsHostDivergence8285 is the fail-on-revert cell.
//
// The fixture is TWO applies, because one cannot see this defect: apply #1
// moves the host and its annotation is present with or without the fix. It is
// the RETRY — the operator's expected next action, and the steady state once
// #7289's r1 established the reachable trigger is persistent — where the
// evidence evaporated.
func TestRetryAfterAbortStillReportsHostDivergence8285(t *testing.T) {
	m := New()
	boom := errors.New("attach userspace shim XDP: generic attach refused")

	// Apply #1: Phase 2 really moved the host, then the attach failed.
	first := newProofResult(nil)
	first.markHostMutated("created VLAN sub-interface")
	err1 := abortErr(first, boom)
	if !strings.Contains(err1.Error(), "created VLAN sub-interface") {
		t.Fatalf("fixture precondition: the FIRST abort must carry the annotation; got %v", err1)
	}
	m.recordHostDivergence(first)

	// Apply #2 — the retry. Phase 2 is converged now, so this compile records
	// nothing of its own: markHostMutated fires only from `if vlanCreated` and
	// from reconcileInterfaceAddresses returning true.
	second := newProofResult(nil)
	if second.HostMutated() {
		t.Fatal("fixture precondition: the retry's own compile must record NOTHING, " +
			"or this test is not exercising the converged-retry path at all")
	}
	m.inheritHostDivergence(second)

	err2 := abortErr(second, boom)
	if !errors.Is(err2, boom) {
		t.Fatalf("the underlying error must survive the annotation; got %v", err2)
	}
	if !strings.Contains(err2.Error(), "created VLAN sub-interface") {
		t.Fatalf("the RETRY reports a bare attach failure and says nothing about the host "+
			"state the first attempt left behind — the box is still diverged and the "+
			"operator is told nothing. got: %v", err2)
	}
	if !strings.Contains(err2.Error(), "no undo") {
		t.Fatalf("the retry's annotation must carry the same instruction as the first "+
			"attempt's, not a degraded one; got %v", err2)
	}
}

// The control, and the property that keeps the annotation worth reading: a
// converged apply that fails for an UNRELATED reason, on a box with no retained
// divergence, must NOT be decorated. `annotateHostMutationOnAbort` states this
// as its own contract — "a converged apply that fails for an unrelated reason
// must not be decorated with a warning about state that did not move, or the
// annotation stops meaning anything" — and a sticky flag is exactly the shape
// that breaks it. Without this cell, "always annotate" passes the test above.
func TestCleanAbortIsNotDecorated8285(t *testing.T) {
	m := New()
	boom := errors.New("attach userspace shim XDP: generic attach refused")

	clean := newProofResult(nil)
	m.inheritHostDivergence(clean)
	err := abortErr(clean, boom)

	if err.Error() != boom.Error() {
		t.Fatalf("an abort on a box with no host divergence must return the error "+
			"UNCHANGED; got %v", err)
	}
}

// A successful apply converges the host and the dataplane, so the retained
// evidence must stop firing. Without this, the first abort of a box's life
// would annotate every abort forever after — the same "stops meaning anything"
// failure as the control above, just delayed.
func TestSuccessfulApplyClearsHostDivergence8285(t *testing.T) {
	m := New()

	aborted := newProofResult(nil)
	aborted.markHostMutated("reconciled interface addresses")
	m.recordHostDivergence(aborted)
	if got := m.debugHostDivergence(); len(got) != 1 {
		t.Fatalf("precondition: the abort must retain its class; got %v", got)
	}

	m.clearHostDivergence() // what the compile success tail does

	after := newProofResult(nil)
	m.inheritHostDivergence(after)
	if after.HostMutated() {
		t.Fatalf("a converged apply must not inherit evidence from an abort that has "+
			"since been converged; got %q", after.hostMutationSummary())
	}
	boom := errors.New("some later unrelated failure")
	if err := abortErr(after, boom); err.Error() != boom.Error() {
		t.Fatalf("after a successful apply, a later unrelated abort must not be "+
			"decorated; got %v", err)
	}
}

// Two aborts moving different classes: the box carries the UNION until a
// success converges it. A "last abort wins" implementation passes every cell
// above and silently drops the earlier class, so the operator is sent to look
// at one of the two things that moved.
func TestSuccessiveAbortsAccumulateDivergence8285(t *testing.T) {
	m := New()

	first := newProofResult(nil)
	first.markHostMutated("created VLAN sub-interface")
	m.recordHostDivergence(first)

	second := newProofResult(nil)
	second.markHostMutated("reconciled interface addresses")
	m.recordHostDivergence(second)

	third := newProofResult(nil)
	m.inheritHostDivergence(third)
	summary := third.hostMutationSummary()
	for _, want := range []string{"created VLAN sub-interface", "reconciled interface addresses"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("the retained divergence must be the UNION of what the aborts moved; "+
				"%q is missing from %q", want, summary)
		}
	}
}

// TestCompileUserspaceShimWiresHostDivergence8285 binds the WIRING. The cells
// above prove the mechanism; they say nothing about whether the compile calls
// it, and CompileUserspaceShim needs netlink and root so no unit test drives it
// end to end.
//
// Both halves are load-bearing and they fail in opposite directions: without
// the inherit the retry loses its annotation (the defect), and without the
// clear every later abort on the box is annotated forever (the control's
// failure, delayed). Order matters too — the inherit must precede the first
// abort site or the aborts it is for cannot see it.
func TestCompileUserspaceShimWiresHostDivergence8285(t *testing.T) {
	fset, file := parseDataplaneFile(t, "loader.go")
	fn := findFuncDecl(t, file, "CompileUserspaceShim")

	line := map[string]int{}
	for _, name := range []string{"CompileConfig", "inheritHostDivergence", "clearHostDivergence", "abortAfterHostMutation"} {
		for _, stmt := range fn.Body.List {
			found := false
			ast.Inspect(stmt, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var got string
				switch f := call.Fun.(type) {
				case *ast.Ident:
					got = f.Name
				case *ast.SelectorExpr:
					got = f.Sel.Name
				}
				if got == name {
					found = true
					if _, seen := line[name]; !seen {
						line[name] = fset.Position(call.Pos()).Line
					}
				}
				return !found
			})
			if found {
				break
			}
		}
	}

	// Non-vacuity FIRST: a missing call would make every ordering check below
	// pass for free.
	for _, name := range []string{"CompileConfig", "inheritHostDivergence", "clearHostDivergence", "abortAfterHostMutation"} {
		if _, ok := line[name]; !ok {
			t.Fatalf("CompileUserspaceShim does not call %s — #8285's retained abort "+
				"evidence is unwired, so a retry after an aborted apply reports a bare "+
				"failure while the box is still diverged", name)
		}
	}
	if line["inheritHostDivergence"] < line["CompileConfig"] {
		t.Fatal("inheritHostDivergence runs BEFORE CompileConfig, so it stamps a result " +
			"that does not exist yet")
	}
	if line["inheritHostDivergence"] > line["abortAfterHostMutation"] {
		t.Fatalf("inheritHostDivergence (line %d) runs AFTER the first abort site (line "+
			"%d), so the aborts it exists for cannot see the retained divergence",
			line["inheritHostDivergence"], line["abortAfterHostMutation"])
	}
	if line["clearHostDivergence"] < line["abortAfterHostMutation"] {
		t.Fatalf("clearHostDivergence (line %d) runs before the abort sites (line %d) — "+
			"it must be on the SUCCESS tail, or it drops the evidence while it is still "+
			"true", line["clearHostDivergence"], line["abortAfterHostMutation"])
	}
}
