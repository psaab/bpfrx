package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Codex PR #6743 r6-B3: the #2114 cell is MONOTONE within a daemon
// lifetime — once it is emptied it is never refilled — and something
// outside this package depends on that.
//
// pkg/api/system.go's systemBuffersHandler takes THREE independent loads of
// the cell and argues that a torn view is byte-identical to an untorn one.
// The argument holds for a cell that only empties: both later loads fail
// closed to the same body the early return produces. It does NOT hold
// across a REFILL — dpProbe() nil skips the userspace arm, and a
// GetMapStats() that then resolved a NEW backend would emit map rows where
// an untorn view of either instant emitted userspace rows.
//
// r5 wrote that the refill schedule was "real rather than hypothetical"
// because "commit-confirmed rollback re-arms the dataplane". Both halves
// were false. The rollback path calls Teardown() and KEEPS the object in
// the cell (bootstrap.go, "Keep the object so a later confirmed commit
// re-arms it via runBootstrapExitStartup"; the same retention contract is
// documented in daemon_dp_live.go and pinned by
// TestDataplaneCell_RollbackRearmRecurrence), so it never empties the cell
// and the scenario's premise never holds there. And no path refills: the
// only production statement that publishes a NON-NIL dataplane is in
// setupDataplaneAndInitialConfig, one boot phase, run once.
//
// A comment cannot notice when that stops being true. This test can. It is
// deliberately NOT a rule about how many times setDataplane may be called —
// clearing the cell is normal and happens on several paths. It is a rule
// about REFILLING it, which is the only thing pkg/api's argument depends
// on. If a legitimate re-publication path is added, the fix is not to add a
// name to the allowlist below and move on: it is to go and correct the
// paragraph in pkg/api/system.go that this pins, and then record the new
// site here with its reason.
var dataplaneRepublishSites = map[string]string{
	"setupDataplaneAndInitialConfig": "boot: the one and only publication, from the " +
		"dataplane-setup phase in Run",
}

// TestDataplaneCellRefilledOnlyAtBoot scans production sources for
// `setDataplane(<non-nil>)` and reports any enclosing function that is not
// the boot publisher.
func TestDataplaneCellRefilledOnlyAtBoot(t *testing.T) {
	t.Parallel()

	got := dataplanePublishSites(t, ".")

	var unexpected []string
	for _, site := range got {
		fn := site[:strings.IndexByte(site, ' ')]
		if _, ok := dataplaneRepublishSites[fn]; !ok {
			unexpected = append(unexpected, site)
		}
	}
	if len(unexpected) > 0 {
		t.Fatalf("the #2114 cell gains a non-nil publication outside boot:\n%s\n\n"+
			"pkg/api/system.go's systemBuffersHandler takes three independent cell loads "+
			"and argues a torn view is byte-identical to an untorn one. That argument is "+
			"valid ONLY for a cell that empties and stays empty; a refill between loads 2 "+
			"and 3 makes it emit map rows where an untorn view would have emitted userspace "+
			"rows. Correct that paragraph before recording the new site here.",
			strings.Join(unexpected, "\n"))
	}

	// The allowlist must not outlive the site it names. An entry that
	// matches nothing means the scan has stopped seeing the publication it
	// was written for — the guard would then be vacuously green over an
	// empty population, which is the failure mode this whole PR keeps
	// finding in its own tests.
	seen := map[string]bool{}
	for _, site := range got {
		seen[site[:strings.IndexByte(site, ' ')]] = true
	}
	for fn := range dataplaneRepublishSites {
		if !seen[fn] {
			t.Fatalf("dataplaneRepublishSites names %q but the scan found no non-nil "+
				"setDataplane call there (found: %v). Either the boot publisher moved — in "+
				"which case this guard is currently checking nothing — or the scan is "+
				"broken.", fn, got)
		}
	}
}

// dataplanePublishSites returns "<function> (<file>:<line>)" for every
// production `setDataplane(x)` whose argument is not the nil literal.
func dataplanePublishSites(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var sites []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel == nil || sel.Sel.Name != "setDataplane" {
					return true
				}
				if len(call.Args) == 1 && isNilIdent(call.Args[0]) {
					// Clearing the cell is not a refill.
					return true
				}
				sites = append(sites, fn.Name.Name+" ("+name+":"+
					strconv.Itoa(fset.Position(call.Pos()).Line)+")")
				return true
			})
		}
	}
	sort.Strings(sites)
	return sites
}

func isNilIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}
