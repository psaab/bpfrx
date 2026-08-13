package userspace

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #6871 round 9 (F2): the guard process_linkcycle.go's TTL block NAMES.
//
// That comment said, of the one residual the TTL still covers — a lease acquired
// outside the daemon's deferred-abandon extent — "There is none today
// (PrepareLinkCycle has a single caller, daemon_apply_dataplane.go), and
// TestLinkCycleLeaseHasExactlyOneAcquisitionSite_6871 fails if one appears."
//
// The factual half was true. The test did not exist. A shipped comment asserting
// an enforcement that is absent is worse than no comment: it is the reason the
// next reader does not add the check.
//
// WHY THIS PARTICULAR GUARD, AND WHY NOW. Round 8 made the lease renew itself.
// That converts the cost of a leaked lease from "suppressed for one TTL" into
// "suppressed until the process restarts", because the heartbeat keeps re-arming
// a deadline nobody is obliged to release. What makes that safe is not the TTL —
// it is that `applyDataplaneAndHACore` defers `abandonLinkCycleLease` over the
// whole extent in which a lease can be taken. A second acquisition site anywhere
// else is outside that defer, and the failure it produces is permanent.
//
// So the property worth enforcing is not "one caller" for its own sake. It is:
// every path that can take a lease is inside a guaranteed release.
//
// reth_hook_wired_5103_test.go does NOT cover this. It parses only
// daemon_apply_dataplane.go and counts programRethMAC /
// programRethMACWithWorkerJoin / programRethMemberMAC — it never looks at
// PrepareLinkCycle, and it never looks outside that one file.

// linkCycleAcquisitionSites is the allowlist: every production CALL of
// PrepareLinkCycle, keyed "<path>:<enclosing func>".
//
// Three entries, and only the first is an acquisition site in its own right —
// the other two are the adapter chain it reaches through
// (Daemon -> dp.Link() -> userspaceLinkController -> Manager, or via
// LegacyDataPlaneAdapter). They are listed rather than pattern-excluded so that
// moving the chain shows up here as a diff rather than as silence.
var linkCycleAcquisitionSites = map[string]string{
	"pkg/daemon/daemon_apply_dataplane.go:programRethMACWithWorkerJoin": "" +
		"the ONLY production acquisition site. It sits inside step 2.6 of " +
		"applyDataplaneAndHACore, which defers abandonLinkCycleLease over its whole " +
		"body, so the lease this takes cannot outlive the apply",
	"pkg/dataplane/userspace/controllers.go:PrepareLinkCycle": "" +
		"adapter hop: userspaceLinkController forwards to Manager",
	"pkg/dataplane/userspace/legacy_dataplane.go:PrepareLinkCycle": "" +
		"adapter hop: LegacyDataPlaneAdapter forwards to Manager",
}

// repoRootFromPackage walks up from the test's working directory to the module
// root. Walking rather than a fixed "../../.." so the guard survives the package
// being moved, which is exactly the kind of change that would otherwise turn it
// into a silent no-op.
func repoRootFromPackage(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find the module root (no go.mod on any parent): this guard " +
				"would scan nothing and pass vacuously")
		}
		dir = parent
	}
}

// callSitesOf returns "<relpath>:<enclosing decl>" for every REFERENCE to the
// named method in non-test Go source under root.
//
// It keys on any *ast.SelectorExpr whose selector is the method — not on
// CallExpr.Fun (#6871 round 10, F2). Two escapes were MEASURED against the
// CallExpr form, each plant being compiling production Go that takes a lease
// with both guards green:
//
//	prep := d.dp.Link().PrepareLinkCycle   // method VALUE: no CallExpr at all
//	prep()                                 // ...called through the variable
//
// A method value is the natural way to write a deferred or stored call, so this
// is not an exotic shape. Selecting the method AT ALL is the thing worth
// noticing; whether the call is syntactically adjacent is not.
//
// It also walks the whole FILE rather than each *ast.FuncDecl body, because a
// package-level initializer is a *ast.GenDecl and was never inspected:
//
//	var takeLease = func(d *Daemon) error { return d.dp.Link().PrepareLinkCycle() }
//
// The stated exclusions all survive the widening, verified at HEAD: a method
// DECLARATION is a FuncDecl whose name is an *ast.Ident, an interface MEMBER is
// a Field name, and a doc comment is not in the AST — none is a SelectorExpr.
// Over-inclusion is the safe direction here: an unrelated type with a
// same-named method would appear as a new entry and be answered for, rather
// than a real acquisition slipping past.
//
// BUILD TAGS are also the safe direction, and this was measured too: ParseFile
// ignores build constraints, so a plant behind `//go:build never_ever_built` IS
// caught.
func callSitesOf(t *testing.T, root, method string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "node_modules", "target":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // not parseable as Go (generated fixtures, testdata)
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		record := func(where string, node ast.Node) {
			ast.Inspect(node, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == method {
					out[rel+":"+where] = true
				}
				return true
			})
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body != nil {
					record(d.Name.Name, d.Body)
				}
			case *ast.GenDecl:
				// var/const initializers run at package init and can take a
				// lease with no enclosing function at all.
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) == 0 {
						continue
					}
					for _, v := range vs.Values {
						record(vs.Names[0].Name, v)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// TestLinkCycleLeaseHasExactlyOneAcquisitionSite_6871 is the guard the TTL
// comment names. It is tree-wide on purpose: LinkController lives in
// pkg/dataplane and any package in the module can hold one.
//
// RED-on-revert: add a `Link().PrepareLinkCycle()` call in any production
// function not on the allowlist and this fails naming it.
func TestLinkCycleLeaseHasExactlyOneAcquisitionSite_6871(t *testing.T) {
	root := repoRootFromPackage(t)
	got := callSitesOf(t, root, "PrepareLinkCycle")

	if len(got) == 0 {
		t.Fatal("found ZERO PrepareLinkCycle call sites tree-wide. The scan is broken, and " +
			"a broken scan makes this guard vacuously green — which is precisely the " +
			"failure this file exists to correct")
	}

	var added, removed []string
	for site := range got {
		if _, ok := linkCycleAcquisitionSites[site]; !ok {
			added = append(added, site)
		}
	}
	for site := range linkCycleAcquisitionSites {
		if !got[site] {
			removed = append(removed, site)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

	if len(added) > 0 {
		t.Errorf("NEW PrepareLinkCycle call site(s), not on the allowlist: %v.\n"+
			"Each one takes a link-cycle lease. Since #6871 round 8 that lease RENEWS "+
			"ITSELF, so one that is never released suppresses the 1 Hz reconcile for the "+
			"life of the process rather than for one TTL. What makes the existing site "+
			"safe is not the TTL — it is that applyDataplaneAndHACore defers "+
			"abandonLinkCycleLease over the whole extent that can take one. Confirm the "+
			"new site is inside a guaranteed release, then add it here with the reason.",
			added)
	}
	if len(removed) > 0 {
		t.Errorf("allowlisted PrepareLinkCycle call site(s) that no longer exist: %v. "+
			"Either the call moved (update the entry) or it was removed (delete it) — a "+
			"stale entry makes the allowlist look like it is constraining something it "+
			"is not", removed)
	}
}

// TestLinkCycleLeaseIsAcquiredOnlyByPrepare_6871 is the inner half, and the one
// the tree-wide scan cannot see.
//
// PrepareLinkCycle is a chokepoint only for callers OUTSIDE this package.
// acquireLinkCycleLease is unexported, so anything in package userspace can take
// a lease without going through it — and would inherit none of the daemon's
// deferred release.
//
// RED-on-revert: call m.acquireLinkCycleLease() from any other production
// function in this package and this fails naming it.
func TestLinkCycleLeaseIsAcquiredOnlyByPrepare_6871(t *testing.T) {
	got := callSitesOf(t, ".", "acquireLinkCycleLease")

	want := map[string]bool{"process_linkcycle.go:PrepareLinkCycle": true}
	var unexpected []string
	for site := range got {
		if !want[site] {
			unexpected = append(unexpected, site)
		}
	}
	sort.Strings(unexpected)

	if len(got) == 0 {
		t.Fatal("found ZERO acquireLinkCycleLease call sites in this package; the scan is " +
			"broken and this guard proves nothing")
	}
	if len(unexpected) > 0 {
		t.Errorf("link-cycle lease acquired outside PrepareLinkCycle: %v. Callers outside "+
			"this package are funnelled through PrepareLinkCycle, whose one production "+
			"caller sits inside the daemon's deferred abandon; an in-package acquisition "+
			"has no such guarantee, and a self-renewing lease that is never released "+
			"suppresses the reconcile loop permanently", unexpected)
	}
	for site := range want {
		if !got[site] {
			t.Errorf("PrepareLinkCycle no longer acquires the lease (%s not found). Either "+
				"the acquisition moved — in which case this guard now constrains nothing — "+
				"or the lease is not being taken at all", site)
		}
	}
}
