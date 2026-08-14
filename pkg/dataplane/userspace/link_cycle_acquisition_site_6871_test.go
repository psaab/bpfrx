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
// PrepareLinkCycle, keyed
//
//	"<path>:<enclosing decl>: <selector source> [<form>]..."
//
// The enclosing decl of a method is RECEIVER-QUALIFIED (see declSiteKey), the
// selector is rendered from source (see refKey), and a form marker appears for
// every way the call is written that the AST cannot prove runs inside the
// enclosing declaration's extent (see classifyRef).
//
// WHAT A KEY MEANS, STATED AT THE STRENGTH IT ACTUALLY HAS (#6871 round 14).
// An unmarked key says: reaching this call requires the named declaration to be
// executing, and the call completes before that declaration returns. A MARKED
// key says the opposite — the AST could establish only that the call is written
// there. Those two claims cannot share a key, which is the whole reason the form
// is in the key: an escaping form cannot come to rest under a key that reads as
// a proof.
//
// Three entries, and only the first is an acquisition site in its own right —
// the other two are the adapter chain it reaches through
// (Daemon -> dp.Link() -> userspaceLinkController -> Manager, or via
// LegacyDataPlaneAdapter). They are listed rather than pattern-excluded so that
// moving the chain shows up here as a diff rather than as silence.
var linkCycleAcquisitionSites = map[string]string{
	"pkg/daemon/daemon_apply_dataplane.go:(*Daemon).programRethMACWithWorkerJoin: " +
		"d.dp.Link().PrepareLinkCycle [in a func literal]": "" +
		"the ONLY production acquisition site. It sits inside step 2.6 of " +
		"applyDataplaneAndHACore, which defers abandonLinkCycleLease over its whole " +
		"body — but it is written in the beforeCycle CALLBACK, so being inside that " +
		"defer is a property of programRethMAC invoking the callback synchronously, " +
		"which no AST fact establishes. The proof is behavioural and lives in the " +
		"test named by linkCycleUnprovenFormBindings",
	"pkg/dataplane/userspace/controllers.go:(userspaceLinkController).PrepareLinkCycle: " +
		"c.manager.PrepareLinkCycle": "" +
		"adapter hop: userspaceLinkController forwards to Manager",
	"pkg/dataplane/userspace/legacy_dataplane.go:(*LegacyDataPlaneAdapter).PrepareLinkCycle: " +
		"m.PrepareLinkCycle": "" +
		"adapter hop: LegacyDataPlaneAdapter forwards to Manager",
}

// linkCycleInPackageAcquisitionSites is the same allowlist for the in-package
// guard below, whose subject is the unexported acquireLinkCycleLease.
var linkCycleInPackageAcquisitionSites = map[string]string{
	"process_linkcycle.go:(*Manager).PrepareLinkCycle: m.acquireLinkCycleLease": "" +
		"the one in-package acquisition, in ordinary statement flow: reaching it " +
		"requires PrepareLinkCycle to be running and it returns before PrepareLinkCycle " +
		"does, so the daemon's deferred abandon covers it",
}

// linkCycleUnprovenFormBindings names, for every allowlisted site whose FORM the
// AST cannot prove temporally contained, the test that carries the proof
// instead. Both allowlists are checked against this map: a marked key with no
// entry here fails, an entry naming a test that does not exist fails, and an
// entry for a key that is no longer allowlisted fails.
//
// That last three-way check is the point. #6871 round 9 built this whole file
// because process_linkcycle.go carried a comment asserting an enforcement that
// did not exist. An allowlist entry whose reason says "the proof is behavioural
// and lives in <test>" is exactly the same shipped assertion, and it decays the
// same way — by the test being renamed or deleted somewhere else entirely.
var linkCycleUnprovenFormBindings = map[string]string{
	"pkg/daemon/daemon_apply_dataplane.go:(*Daemon).programRethMACWithWorkerJoin: " +
		"d.dp.Link().PrepareLinkCycle [in a func literal]": "" +
		"TestRethMACHookRunsOnTheCallersGoroutine_6871",
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
//	calls    the selector IS a CallExpr's callee. Reaching it requires the
//	         enclosing declaration to be executing, so "which declaration" is
//	         at least a fact about the call and the allowlist means something.
//	         WHEN it runs relative to that declaration is a separate question,
//	         answered by the form markers classifyRef puts in the key.
//	escapes  every other form. The selector produces a VALUE — a method value,
//	         an argument, a struct field, a return — and a value can be stored
//	         and invoked from anywhere, at any time, by anyone. The enclosing
//	         declaration bounds nothing, so there is no key that could honestly
//	         file it, and it is reported as a violation on its own.
type methodRefs struct {
	calls   map[string]bool // see refKey
	escapes []string        // "<relpath>:<line>: <expr> in <enclosing decl>"
}

// The form markers. They appear in a call's key, so a form the AST cannot prove
// temporally contained can never land on the same key as one it can.
const (
	markFuncLit = "[in a func literal]"
	markGo      = "[started by a go statement]"
)

// refKey names one reference: where it is written, and — for a call — how.
//
// The selector is rendered FROM SOURCE rather than reduced to the method name
// (#6871 round 14). Round 13 keyed a call as "<path>:<decl>" alone, so every
// call of that NAME inside one declaration collapsed onto one boolean, and an
// unrelated same-named field or package function written in the allowlisted
// declaration held the expected key up after the real acquisition was deleted.
// That was measured, as compiling production Go with BOTH guards green while
// the manager took no lease at all:
//
//	type leaseHooks struct{ acquireLinkCycleLease []func() }
//	var hooks = leaseHooks{...}
//	// inside (*Manager).PrepareLinkCycle, INSTEAD of m.acquireLinkCycleLease():
//	hooks.acquireLinkCycleLease[0]()
//
// Rendering the selector separates "m.acquireLinkCycleLease" from
// "hooks.acquireLinkCycleLease", so the substitution shows up as one key gone
// and one key added.
//
// What this does NOT reach is a decoy whose selector has the same SOURCE TEXT
// and a different type — say d.dp.Link() coming to return something else. Only
// a type-checked scan distinguishes those, and this guard deliberately does not
// run go/types over the whole module. The claim is therefore "identity by
// written form", not "identity by resolved method".
func refKey(rel, where string, sel *ast.SelectorExpr, marks []string) string {
	key := rel + ":" + where + ": " + types.ExprString(sel)
	for _, m := range marks {
		key += " " + m
	}
	return key
}

// invokedBy reports the CallExpr that directly invokes chain[i] — that is,
// chain[i], possibly parenthesised, is the call's Fun — and where that call sits
// in the chain. chain is an ancestor chain: chain[k] is the parent of chain[k+1].
//
// Parentheses are unwrapped because `(m.f)()` really is a call of m.f. INDEX
// expressions are NOT (#6871 round 14). Round 13 unwrapped *ast.IndexExpr here
// on the theory that an index around a callee is generic instantiation, which
// bought nothing and cost a misclassification:
//
//   - a method cannot have its own type parameters in Go, so there is no
//     m.Method[T]() to rescue; a method on a generic receiver is written
//     Box[int].M(b), where the selector is ALREADY the callee and needs no
//     unwrapping; and
//   - h.hooks[0]() indexes a slice of funcs, so the ELEMENT is the callee and
//     the selector h.hooks is not called at all — yet the unwrap recorded it
//     as a call.
//
// Credit where the measurement puts it: restoring this unwrap on its own leaves
// the decoy in refKey's comment RED, because refKey no longer lets it reach the
// allowlisted key. What round 13 needed for that decoy to pass was the unwrap
// AND the name-only key together. Dropping the unwrap is therefore a
// classification fix — the decoy is now reported as the escape it is — not the
// thing that closes the hole.
func invokedBy(chain []ast.Node, i int) (*ast.CallExpr, int, bool) {
	child := ast.Node(chain[i])
	for k := i - 1; k >= 0; k-- {
		if p, ok := chain[k].(*ast.ParenExpr); ok && ast.Node(p.X) == child {
			child = chain[k]
			continue
		}
		if c, ok := chain[k].(*ast.CallExpr); ok && ast.Node(c.Fun) == child {
			return c, k, true
		}
		return nil, 0, false
	}
	return nil, 0, false
}

// classifyRef answers two questions about the reference at the end of chain:
// whether it is a CALL at all, and — if it is — every way it is written that
// stops "written in declaration D" from implying "runs inside D's extent".
//
// WHY CALLEE POSITION WAS NOT ENOUGH (#6871 round 14). Round 13 established
// position and then attributed every callee selector anywhere under a FuncDecl
// to that declaration, function literals included. So this compiled with both
// guards green:
//
//	var escapedAcquire func()
//	// inside the allowlisted (*Manager).PrepareLinkCycle:
//	escapedAcquire = func() { m.mu.Lock(); defer m.mu.Unlock(); m.acquireLinkCycleLease() }
//
//	func TakeLeaseOutsideApply() { escapedAcquire() }  // no selector: invisible
//
// The inner selector IS a callee, so it recorded as the expected call; the later
// invocation names nothing. Lexically inside, temporally outside — which is the
// only thing that matters for a lease whose safety comes from a deferred abandon
// in the caller. `go m.acquireLinkCycleLease()` was green the same way: an
// ordinary call, on a goroutine that may outlive the whole apply.
//
// So the containment rules, and they are about EXECUTION, not spelling:
//
//	ordinary flow  contained. Reaching the call requires D to be running.
//	defer f()      contained. Runs before D returns, which is the property
//	               the deferred abandon needs — it does not need "before the
//	               statement after it".
//	func(){...}()  contained, and `defer func(){...}()` too: an immediately
//	               invoked literal runs within D like any other statement.
//	go ...()       NOT contained. The goroutine is scheduled, not run, and D
//	               can return first. Marked.
//	a literal that is not immediately invoked
//	               NOT contained. The value can be stored and called at any
//	               later time, which is exactly the escape above. Marked.
//
// AND THE HONEST LIMIT, because this is where the AST stops. A marker means
// "not proven contained", never "proven escaping": the daemon's own production
// site is a callback literal that programRethMAC happens to invoke
// synchronously, so it IS contained — by a fact about a function in another
// package that no amount of local AST inspection can see. Establishing
// containment in general would need whole-program call-graph and escape
// analysis, which this guard does not do and does not claim. What it does is
// refuse to let an unproven form share a key with a proven one, so every marked
// site has to be allowlisted deliberately and carry a named behavioural proof
// (linkCycleUnprovenFormBindings).
func classifyRef(chain []ast.Node) (marks []string, isCall bool) {
	call, callIdx, ok := invokedBy(chain, len(chain)-1)
	if !ok {
		return nil, false
	}
	add := func(m string) {
		for _, have := range marks {
			if have == m {
				return
			}
		}
		marks = append(marks, m)
	}
	if callIdx > 0 {
		if g, ok := chain[callIdx-1].(*ast.GoStmt); ok && g.Call == call {
			add(markGo)
		}
	}
	// Every function-literal boundary between the call and the declaration it
	// is written in. Each one that is not immediately invoked defers the call
	// to whenever that literal's value is invoked, if ever.
	for j := callIdx - 1; j >= 0; j-- {
		if _, ok := chain[j].(*ast.FuncLit); !ok {
			continue
		}
		litCall, litIdx, invoked := invokedBy(chain, j)
		if !invoked {
			add(markFuncLit)
			continue
		}
		if litIdx > 0 {
			if g, ok := chain[litIdx-1].(*ast.GoStmt); ok && g.Call == litCall {
				add(markGo)
			}
		}
	}
	return marks, true
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
// rather than argued: recording a method value under its enclosing declaration
// files it under whatever key that declaration has, and when the value is taken
// INSIDE the allowlisted function that key is the allowlisted one. So the rule
// is positional — the selector must BE the callee — and anything else is
// rejected outright rather than keyed. classifyRef then answers the second
// question position does not answer, WHEN the call runs; read its comment for
// why callee position alone was still green against two live escapes.
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
// OVER-INCLUSION IS THE SAFE DIRECTION FOR WHAT IT ADDS, NOT FOR WHAT IT KEEPS
// ALIVE, and round 13's comment overstated this (#6871 round 14). Adding a
// reference does fail safely: an unrelated same-named method shows up as a new
// key or a new escape and gets answered for. But the allowlist ALSO asserts
// that each listed site still exists, and that half is defeated by any decoy
// that reproduces the key — which under round 13's name-only key meant any
// same-named call at all. refKey now spells the whole selector, so a decoy has
// to reproduce the exact source text; see refKey for the residual that leaves.
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
			// One walk carrying the ancestor chain, because both questions —
			// is this selector the callee, and what encloses that call — are
			// about the reference's POSITION in the tree, which a callback with
			// no parent context cannot see. ast.Inspect visits a node before
			// its children and re-visits nil after them, so pushing on the way
			// in and popping on the way out keeps chain equal to the strict
			// ancestors of the node in hand.
			var chain []ast.Node
			ast.Inspect(node, func(n ast.Node) bool {
				if n == nil {
					chain = chain[:len(chain)-1]
					return true
				}
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == method {
					full := make([]ast.Node, len(chain)+1)
					copy(full, chain)
					full[len(chain)] = sel
					if marks, isCall := classifyRef(full); isCall {
						refs.calls[refKey(rel, where, sel, marks)] = true
					} else {
						refs.escapes = append(refs.escapes, fmt.Sprintf("%s:%d: %s in %s",
							rel, fset.Position(sel.Pos()).Line, types.ExprString(sel), where))
					}
				}
				chain = append(chain, n)
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

// testFuncNamed reports whether a Go test function of that name exists anywhere
// under root. Deliberately a whole-tree scan and not a lookup in this package:
// the proof a marked site leans on lives wherever the dependency lives, which
// for the daemon's callback site is pkg/daemon.
func testFuncNamed(t *testing.T, root, name string) bool {
	t.Helper()
	found := false
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || found {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "node_modules", "target":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Recv == nil && fd.Name.Name == name {
				found = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s for %s: %v", root, name, err)
	}
	return found
}

// requireUnprovenFormsAreBound enforces the contract on marked keys in both
// directions: every allowlisted site whose form the AST cannot prove contained
// must name a test in linkCycleUnprovenFormBindings, and every test named there
// must exist and belong to a site that is still allowlisted.
//
// Without the third check this file would ship the exact defect it was written
// to correct — a reason asserting a proof that has since been renamed away.
func requireUnprovenFormsAreBound(t *testing.T, root string, sites map[string]string) {
	t.Helper()
	for key := range sites {
		// The markers themselves, not "contains a bracket": a selector's source
		// text can carry brackets of its own (m.hooks[0].Method), and a proxy
		// that reads those as a form marker would demand a behavioural proof
		// for a call that is in ordinary flow.
		if !strings.Contains(key, markFuncLit) && !strings.Contains(key, markGo) {
			continue
		}
		bound, ok := linkCycleUnprovenFormBindings[key]
		if !ok {
			t.Errorf("allowlisted site %q is written in a form the AST cannot prove runs "+
				"inside the enclosing declaration's extent, and nothing else proves it "+
				"either. Either write the call in ordinary flow, or add the test that "+
				"establishes containment to linkCycleUnprovenFormBindings", key)
			continue
		}
		if !testFuncNamed(t, root, bound) {
			t.Errorf("site %q says its containment is proved by %s, and no such test exists "+
				"in the tree. That is the failure this whole file was written to correct in "+
				"round 9: a shipped assertion naming an enforcement that is absent",
				key, bound)
		}
	}
	for key, bound := range linkCycleUnprovenFormBindings {
		// Against BOTH allowlists, not just the caller's: a binding is stale
		// only if no allowlist anywhere still names its site.
		if _, listed := linkCycleAcquisitionSites[key]; listed {
			continue
		}
		if _, listed := linkCycleInPackageAcquisitionSites[key]; listed {
			continue
		}
		t.Errorf("%s is named as the containment proof for %q, which is not an allowlisted "+
			"site any more. A binding for a site that no longer exists makes the map look "+
			"like it is carrying weight it is not", bound, key)
	}
}

// TestLinkCycleLeaseHasExactlyOneAcquisitionSite_6871 is the guard the TTL
// comment names. It is tree-wide on purpose: LinkController lives in
// pkg/dataplane and any package in the module can hold one.
//
// RED-on-revert: add a `Link().PrepareLinkCycle()` call in any production
// function not on the allowlist and this fails naming it. Take a method VALUE of
// it anywhere, allowlisted function included, and it fails naming that too. Move
// the existing call into a function literal, or start it with `go`, and the key
// changes form and fails both as an unlisted site and as a listed one gone.
func TestLinkCycleLeaseHasExactlyOneAcquisitionSite_6871(t *testing.T) {
	root := repoRootFromPackage(t)
	refs := callSitesOf(t, root, "PrepareLinkCycle")
	got := refs.calls
	requireUnprovenFormsAreBound(t, root, linkCycleAcquisitionSites)

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
			"new site is inside a guaranteed release, then add it here with the reason. "+
			"A key carrying %s or %s says the call is only written in that declaration "+
			"and may run after it has returned — that one needs a behavioural proof in "+
			"linkCycleUnprovenFormBindings, not a sentence.",
			added, markFuncLit, markGo)
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
// naming that too (#6871 round 13). Wrap it in a func literal that is not
// immediately invoked, or start it with `go`, and it fails naming that too
// (#6871 round 14) — while an ordinary call to the same method one line away
// keeps satisfying the allowlist, which is what makes the failure a judgement
// about the FORM rather than about the name being present.
func TestLinkCycleLeaseIsAcquiredOnlyByPrepare_6871(t *testing.T) {
	refs := callSitesOf(t, ".", "acquireLinkCycleLease")
	got := refs.calls
	requireUnprovenFormsAreBound(t, repoRootFromPackage(t), linkCycleInPackageAcquisitionSites)

	want := linkCycleInPackageAcquisitionSites
	var unexpected []string
	for site := range got {
		if _, ok := want[site]; !ok {
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
