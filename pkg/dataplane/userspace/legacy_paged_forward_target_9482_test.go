package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// #9482 — the adapter's paged forwarder must delegate to the Manager's PAGED
// method, not to the unpaged one it sits next to.
//
// WHY A SOURCE-LEVEL CELL, and why a behavioural one cannot do this job. Both
// candidate delegations compile, both satisfy `pkg/daemon`'s
// `userspaceSessionExporter`, and both make every other #9482 cell green — the
// interface only names a signature. They are also INDISTINGUISHABLE at runtime
// without a live helper: `Manager.ExportOwnerRGSessionsPaged` and
// `Manager.ExportOwnerRGSessions` each begin with the same `m.proc == nil` guard
// returning the identical "userspace dataplane helper not running" error, so any
// fixture that does not start a helper gets the same answer from both. Verified,
// not assumed — see manager_status.go and owner_rg_export_paging_9344.go.
//
// WHAT THE WRONG DELEGATION WOULD COST, which is why this is worth a cell rather
// than a comment. `ExportOwnerRGSessions(rgIDs, 0)` asks for the UNBOUNDED set.
// #9344 exists because that crosses the helper's 64 MiB control-response cap at
// roughly 7.8k sessions per worker, and a truncated response is not a smaller
// window — since #5085 the receiver reconciles authoritatively against the window
// and DELETES every eligible session missing from it. So a forwarder that
// compiles, type-asserts, and reads as a fix would restore the exact permanent
// cold-prime failure on a busy cluster that #9344 was written to remove, while
// every assertion about the type system stayed green.
//
// The cell is deliberately narrow: it pins THIS method's delegation target, not a
// general "every forwarder forwards to its namesake" rule. A blanket rule over
// ~40 hand-written forwarders would be a different change with its own false
// positives, and this issue has no evidence about the others.
func TestLegacyAdapterPagedExportForwardsToThePagedManagerMethod9482(t *testing.T) {
	const method = "ExportOwnerRGSessionsPaged"

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "legacy_dataplane.go", nil, 0)
	if err != nil {
		t.Fatalf("parse legacy_dataplane.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if !ok || d.Name.Name != method || d.Recv == nil {
			continue
		}
		fn = d
	}
	if fn == nil {
		t.Fatalf("#9482: LegacyDataPlaneAdapter has no %s method at all. That is the "+
			"defect itself: dpuserspace.Boot() publishes this adapter, pkg/daemon's "+
			"userspaceSessionExporter names exactly this method, and without it the "+
			"runtime type assertion in userspaceBulkSnapshot fails and the HA cold-prime "+
			"bulk sync never runs", method)
	}

	// Collect every method name this body calls on its resolved manager.
	called := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			called[sel.Sel.Name] = true
		}
		return true
	})

	if !called[method] {
		var names []string
		for n := range called {
			names = append(names, n)
		}
		t.Errorf("#9482: the adapter's %s does not call the Manager's %s. It calls %v.\n"+
			"  Delegating to the UNPAGED ExportOwnerRGSessions instead compiles, satisfies "+
			"userspaceSessionExporter, and leaves every other #9482 cell green — while "+
			"asking for the unbounded set, which is exactly the >64 MiB truncation #9344 "+
			"removed. A truncated window is not a smaller window: since #5085 the receiver "+
			"DELETES every eligible session missing from it.", method, method, names)
	}
	if called["ExportOwnerRGSessions"] {
		t.Errorf("#9482: the adapter's %s calls the UNPAGED ExportOwnerRGSessions. "+
			"See above — that reintroduces #9344's unbounded request", method)
	}
}
