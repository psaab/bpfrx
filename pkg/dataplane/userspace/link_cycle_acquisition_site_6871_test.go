package userspace

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
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
// PrepareLinkCycle, keyed "<path>:<enclosing decl>" — and the enclosing decl of
// a method is RECEIVER-QUALIFIED (see declSiteKey).
//
// "CALL" is exact, and is what makes this map able to constrain anything
// (#6871 round 13). A key names the function a call is written IN, which bounds
// the acquisition only if invoking it requires being there. That holds for a
// call and fails for a method VALUE, which can be stored and invoked from
// anywhere later — so callSitesOf keys only selectors in CALLEE position here,
// and rejects every other reference form outright instead of filing it under
// its enclosing declaration.
//
// Three entries, and only the first is an acquisition site in its own right —
// the other two are the adapter chain it reaches through
// (Daemon -> dp.Link() -> userspaceLinkController -> Manager, or via
// LegacyDataPlaneAdapter). They are listed rather than pattern-excluded so that
// moving the chain shows up here as a diff rather than as silence.
var linkCycleAcquisitionSites = map[string]string{
	"pkg/daemon/daemon_apply_dataplane.go:(*Daemon).programRethMACWithWorkerJoin": "" +
		"the ONLY production acquisition site. It sits inside step 2.6 of " +
		"applyDataplaneAndHACore, which defers abandonLinkCycleLease over its whole " +
		"body, so the lease this takes cannot outlive the apply",
	"pkg/dataplane/userspace/controllers.go:(userspaceLinkController).PrepareLinkCycle": "" +
		"adapter hop: userspaceLinkController forwards to Manager",
	"pkg/dataplane/userspace/legacy_dataplane.go:(*LegacyDataPlaneAdapter).PrepareLinkCycle": "" +
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

// declSiteKey names the enclosing declaration for a key, QUALIFIED BY RECEIVER
// TYPE when it is a method: "(*Daemon).programRethMACWithWorkerJoin".
//
// #6871 round 11. Go permits two declarations of one name in one file when the
// receivers differ, so a bare name is not a unique key — and the collision is
// absorbed SILENTLY by an allowlist entry that already carries that name. The
// escape was measured, as compiling production Go taking a real lease with both
// guards green:
//
//	type rethMACRetry struct{ d *Daemon }
//	// same file, same name, different receiver — key collides with the entry below
//	func (r *rethMACRetry) programRethMACWithWorkerJoin(n string) error {
//	    return r.d.dp.Link().PrepareLinkCycle()   // a REAL second acquisition
//	}
//
// That is exactly the failure the tree-wide guard exists to prevent: an
// acquisition outside applyDataplaneAndHACore's deferred abandon, whose leaked
// lease is permanent since round 8 made the lease renew itself. The in-package
// guard had the same hole against a shadow method in process_linkcycle.go.
//
// types.ExprString rather than a hand-rolled type switch, so a pointer receiver,
// a generic one (Foo[T]) and any shape added later all render instead of
// collapsing into a silent default.
//
// RED-on-revert without a plant: return d.Name.Name here and BOTH guards fail
// immediately — every allowlisted key becomes "no longer exists" and every real
// site becomes "not on the allowlist". The key format and the allowlist are each
// other's check.
//
// KNOWN LIMIT, stated rather than papered over. Neither guard sees
//
//	reflect.ValueOf(dp.Link()).MethodByName("PrepareLinkCycle").Call(nil)
//
// because there is no SelectorExpr naming the method at all — the name is a
// string literal. Matching the literal too would fire on every doc comment and
// error string that spells it, so this guard does not claim to cover reflective
// calls, and no reviewer should read it as doing so.
func declSiteKey(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	return "(" + types.ExprString(d.Recv.List[0].Type) + ")." + d.Name.Name
}

// methodRefs is what a scan yields, and the split is the whole point (#6871
// round 13). A reference to the method is one of two things, and only one of
// them can be governed by an allowlist keyed on the enclosing declaration:
//
//	calls    the selector IS a CallExpr's callee. Invoking it requires being
//	         in that declaration, so "which declaration" bounds "who can take
//	         a lease" and the allowlist means something.
//	escapes  every other form. The selector produces a VALUE — a method value,
//	         an argument, a struct field, a return — and a value can be stored
//	         and invoked from anywhere, at any time, by anyone. The enclosing
//	         declaration bounds nothing, so there is no key that could honestly
//	         file it, and it is reported as a violation on its own.
type methodRefs struct {
	calls   map[string]bool // "<relpath>:<enclosing decl>"
	escapes []string        // "<relpath>:<line>: <expr> in <enclosing decl>"
}

// unwrapCallee strips the wrappers Go allows between a CallExpr and the selector
// it actually calls, so `(m.f)()` and a generic `m.f[T]()` classify as CALLS
// rather than as escapes. Without this the guard would be loud in the wrong
// direction — a legitimate parenthesized call reported as a leaked method value.
func unwrapCallee(e ast.Expr) ast.Expr {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.IndexExpr: // generic instantiation: f[T]()
			e = x.X
		case *ast.IndexListExpr: // f[T1, T2]()
			e = x.X
		default:
			return e
		}
	}
}

// callSitesOf classifies every REFERENCE to the named method in non-test Go
// source under root, splitting calls from escapes per methodRefs above. The
// enclosing decl of a method is receiver-qualified per declSiteKey.
//
// WHY POSITION AND NOT JUST THE NAME (#6871 round 13). Round 10 widened this
// from CallExpr.Fun to any *ast.SelectorExpr, because a method value has no
// CallExpr at all:
//
//	prep := d.dp.Link().PrepareLinkCycle   // method VALUE
//	prep()                                 // ...called through the variable
//
// That widening was necessary and NOT sufficient, and the gap was compiled
// rather than argued. Recording a method value under its enclosing declaration
// files it under whatever key that declaration has — and when the method value
// is taken INSIDE the allowlisted function, that key is the allowlisted one:
//
//	var escapedAcquire func()
//
//	// inside (*Manager).PrepareLinkCycle — the one allowlisted site:
//	take := m.acquireLinkCycleLease
//	escapedAcquire = func() { m.mu.Lock(); defer m.mu.Unlock(); take() }
//	take()
//
//	func TakeLeaseOutsideApply() { escapedAcquire() }  // no selector: invisible
//
// The only selector naming the method sits in the allowlisted declaration, so
// the pre-round-13 scan produced exactly the expected key and BOTH guards
// passed. Calling TakeLeaseOutsideApply once the daemon's apply has returned
// takes a lease outside the deferred-abandon extent, and since round 8 made the
// lease renew itself that suppresses the 1 Hz reconcile for the life of the
// process. This is the third escape of one family in this campaign — #6676's
// binding_slot callee substitution and #6706's `*x.field = CLI{}` write form —
// all of them an AST matcher matching a NAME where the property is about a
// POSITION.
//
// So the rule is positional: the selector must BE the callee. Anything else is
// rejected outright rather than keyed, because there is no declaration whose
// name would honestly bound it.
//
// It also walks the whole FILE rather than each *ast.FuncDecl body, because a
// package-level initializer is a *ast.GenDecl and was never inspected:
//
//	var takeLease = func(d *Daemon) error { return d.dp.Link().PrepareLinkCycle() }
//
// The stated exclusions all survive both passes, verified at HEAD: a method
// DECLARATION is a FuncDecl whose name is an *ast.Ident, an interface MEMBER is
// a Field name, and a doc comment is not in the AST — none is a SelectorExpr, so
// none is a call and none is an escape.
//
// Over-inclusion stays the safe direction: an unrelated type with a same-named
// method appears as a new call-site entry or a new escape and gets answered for,
// rather than a real acquisition slipping past. If a legitimate non-callee use
// ever appears, the fix is to state why that value cannot be invoked outside a
// guaranteed release — not to go back to keying it by its neighbours.
//
// BUILD TAGS are also the safe direction, and this was measured too: ParseFile
// ignores build constraints, so a plant behind `//go:build never_ever_built` IS
// caught.
//
// KNOWN LIMIT, unchanged: a reflective call names the method with a string
// literal and has no SelectorExpr at all. See declSiteKey.
func callSitesOf(t *testing.T, root, method string) methodRefs {
	t.Helper()
	refs := methodRefs{calls: map[string]bool{}}
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
			// Pass 1: which selector NODES are somebody's callee. Node identity,
			// not name — two selectors spelling the same thing in one expression
			// must classify independently.
			callees := map[*ast.SelectorExpr]bool{}
			ast.Inspect(node, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := unwrapCallee(call.Fun).(*ast.SelectorExpr); ok {
					callees[sel] = true
				}
				return true
			})
			// Pass 2: classify every selector naming the method.
			ast.Inspect(node, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != method {
					return true
				}
				if callees[sel] {
					refs.calls[rel+":"+where] = true
					return true
				}
				refs.escapes = append(refs.escapes, fmt.Sprintf("%s:%d: %s in %s",
					rel, fset.Position(sel.Pos()).Line, types.ExprString(sel), where))
				return true
			})
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body != nil {
					record(declSiteKey(d), d.Body)
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
	sort.Strings(refs.escapes)
	return refs
}

// reportLeaseRefEscapes fails when the method is referenced without being
// called. Both guards below owe this for their own scope: the tree-wide one
// because a method value taken in pkg/daemon escapes it exactly as readily, the
// in-package one because acquireLinkCycleLease is where the escape was compiled.
func reportLeaseRefEscapes(t *testing.T, method string, escapes []string) {
	t.Helper()
	if len(escapes) == 0 {
		return
	}
	t.Errorf("%s is REFERENCED WITHOUT BEING CALLED at: %v.\n"+
		"Each of those evaluates to a callable value that can be stored and invoked "+
		"anywhere, at any time — including after the daemon's apply has returned, which "+
		"is outside the deferred abandonLinkCycleLease that is the only thing bounding a "+
		"lease. The enclosing declaration therefore constrains nothing, so no allowlist "+
		"entry can honestly cover one, and being written inside the allowlisted function "+
		"is not a defence: that is precisely where the measured escape put it. Call the "+
		"method directly, or state here why this particular value cannot outlive a "+
		"guaranteed release.", method, escapes)
}

// TestLinkCycleLeaseHasExactlyOneAcquisitionSite_6871 is the guard the TTL
// comment names. It is tree-wide on purpose: LinkController lives in
// pkg/dataplane and any package in the module can hold one.
//
// RED-on-revert: add a `Link().PrepareLinkCycle()` call in any production
// function not on the allowlist and this fails naming it. Take a method VALUE of
// it anywhere, allowlisted function included, and it fails naming that too.
func TestLinkCycleLeaseHasExactlyOneAcquisitionSite_6871(t *testing.T) {
	root := repoRootFromPackage(t)
	refs := callSitesOf(t, root, "PrepareLinkCycle")
	got := refs.calls

	if len(got)+len(refs.escapes) == 0 {
		t.Fatal("found ZERO PrepareLinkCycle references tree-wide. The scan is broken, and " +
			"a broken scan makes this guard vacuously green — which is precisely the " +
			"failure this file exists to correct")
	}
	reportLeaseRefEscapes(t, "PrepareLinkCycle", refs.escapes)

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
// function in this package and this fails naming it. Bind it to a variable
// instead of calling it — anywhere, PrepareLinkCycle included — and it fails
// naming that too (#6871 round 13).
func TestLinkCycleLeaseIsAcquiredOnlyByPrepare_6871(t *testing.T) {
	refs := callSitesOf(t, ".", "acquireLinkCycleLease")
	got := refs.calls

	want := map[string]bool{"process_linkcycle.go:(*Manager).PrepareLinkCycle": true}
	var unexpected []string
	for site := range got {
		if !want[site] {
			unexpected = append(unexpected, site)
		}
	}
	sort.Strings(unexpected)

	if len(got)+len(refs.escapes) == 0 {
		t.Fatal("found ZERO acquireLinkCycleLease references in this package; the scan is " +
			"broken and this guard proves nothing")
	}
	reportLeaseRefEscapes(t, "acquireLinkCycleLease", refs.escapes)
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
