package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #6827 round 8: two guards over the SCOPE of drainLeg's promise, as opposed to
// its behaviour. Both exist because the promise is stated in three places
// (listenerLeg.drained, Server.HTTPSLegDrainedForTest, pkg/api/README.md) and a
// stated invariant with nothing holding it is how a later change inherits a
// guarantee that was never true.

// TestLegDrainTimeoutDefault_6827 pins the SHIPPED graceful-drain deadline.
//
// legDrainTimeout is a var so a test can reach the deadline arm cheaply, and a
// var is assignable: a cell that forgot to restore it, or an edit that "tuned"
// it, would change production behaviour with every existing test still green
// (they either set their own value or never reach the deadline). This asserts
// the value the daemon actually ships with.
func TestLegDrainTimeoutDefault_6827(t *testing.T) {
	if legDrainTimeout != 5*time.Second {
		t.Fatalf("the shipped graceful-drain deadline changed to %v; production never assigns "+
			"legDrainTimeout, so if this moved it moved because a test leaked its override or "+
			"someone retuned it without saying so (#6827 round 8)", legDrainTimeout)
	}
}

// TestNoHijackerInThisPackage_6827 is the GATE behind drainLeg's one documented
// exception.
//
// Go excludes hijacked connections from both halves of the drain — Shutdown
// "does not attempt to close nor wait for hijacked connections such as
// WebSockets", and Close "does not attempt to close (and does not even know
// about)" them — and a hijacked conn is deleted from srv.activeConn when it is
// taken over. So a hijacked connection can outlive drainLeg entirely, with
// `drained` stored and the leg reaped from Server.retiring, still usable by a
// client under a credential policy nothing will ever tighten again. The
// force-close does not close that hole and cannot: the handle is gone.
//
// Two reviewers independently observed that pkg/api contains no Hijacker today
// and read that as closing the case. It does not — it makes the case
// UNREACHABLE, which is a property of the current code rather than of the
// design, and the first person to add a WebSocket endpoint inherits an
// invariant that silently stops holding. This test converts "absent" into
// "refused", so that person is told at the point of the change.
//
// It scans the AST rather than the file text so a comment about hijacking (this
// one, and drainLeg's) is not a false positive; it looks for the two forms that
// can actually take a connection over — a type assertion to http.Hijacker, and
// a call to a .Hijack() method.
func TestNoHijackerInThisPackage_6827(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var scanned int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.TypeAssertExpr:
				if sel, ok := v.Type.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == "Hijacker" {
					t.Errorf("%s: %s asserts to a Hijacker. A hijacked connection is invisible to "+
						"BOTH http.Server.Shutdown and http.Server.Close, so it outlives drainLeg "+
						"with listenerLeg.drained stored — the flag pruneRetiredLocked reads as "+
						"'nothing left for a revocation to reach'. Before adding this, drainLeg "+
						"needs to track hijacked conns (an http.Server.ConnState hook fires with "+
						"StateHijacked and hands you the net.Conn) and close them itself, or the "+
						"invariant in listenerLeg.drained and pkg/api/README.md must be narrowed "+
						"again to exclude this endpoint (#6827 round 8).", fset.Position(v.Pos()), name)
				}
			case *ast.SelectorExpr:
				if v.Sel != nil && v.Sel.Name == "Hijack" {
					t.Errorf("%s: %s calls Hijack. See the Hijacker note above — the drain cannot "+
						"reach a hijacked connection (#6827 round 8).", fset.Position(v.Pos()), name)
				}
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("scanned NO production files: the gate would pass vacuously")
	}
}
