package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// allowedSetUserClassCallers is the receiver-aware allowlist of production
// functions permitted to call CLI.SetUserClass, keyed `<pkg-relpath>::[Recv.]func`
// (mirrors the pkg/linuxsock and pkg/fsatomic canary keys).
//
// SetUserClass is the ONE write to the RBAC class, and #6701 was a bad value
// reaching it. The fail-closed default therefore only holds while every write
// goes through the resolver: a second call site that computed its own class —
// from `$USER`, from a gRPC-supplied name, or from a "default to super-user"
// convenience — would reopen the hole without touching any of the code the
// other tests cover.
var allowedSetUserClassCallers = map[string]string{
	"daemon::applyCLILoginClass": "the single #6701 resolution site (cli.ResolveLoginClass + osident.Current)",
}

// TestSetUserClassHasOneProductionCaller_6701 enumerates every production call
// to SetUserClass across pkg/ and cmd/ and requires each to be allowlisted.
//
// FAIL-ON-REVERT: add a `shell.SetUserClass("super-user")` anywhere else — the
// exact shape of the #6701 defect — and this test names the file and line and
// goes RED.
//
// Method note: the check is on the SELECTOR name, so it catches the call
// regardless of the receiver variable's name or type inference. A same-named
// method on an unrelated type would be a false positive; there is none today,
// and a false positive here is a prompt to think rather than a silent pass.
func TestSetUserClassHasOneProductionCaller_6701(t *testing.T) {
	type call struct{ key, pos string }
	var unexpected []call
	seen := map[string]bool{}
	var filesScanned int

	for _, root := range productionRoots(t) {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				if path != root && skipCanaryDir(d.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			filesScanned++
			pkgRel := pkgRelKeyFor(path)

			var enclosing string
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok {
					enclosing = funcKeyFor(pkgRel, fn)
					return true
				}
				// A SetUserClass selector in ANY position — called, or taken as
				// a method value (`f := shell.SetUserClass`). The method-value
				// form is a class write too, and matching only CallExpr.Fun
				// let it walk straight past this allowlist (#6706 MINOR-4).
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "SetUserClass" {
					return true
				}
				seen[enclosing] = true
				if _, allowed := allowedSetUserClassCallers[enclosing]; !allowed {
					unexpected = append(unexpected, call{
						key: enclosing,
						pos: fset.Position(sel.Pos()).String(),
					})
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if filesScanned == 0 {
		t.Fatal("scanned no production files — the walk is not reaching the source it checks")
	}

	for _, c := range unexpected {
		t.Errorf("%s (%s) calls SetUserClass but is not allowlisted — every RBAC class write must "+
			"go through cli.ResolveLoginClass so the fail-closed default cannot be bypassed (#6701)",
			c.key, c.pos)
	}

	// The allowlist must not rot into a list of functions that no longer exist:
	// a stale entry would silently permit a future function of the same name.
	var stale []string
	for key := range allowedSetUserClassCallers {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("allowlisted SetUserClass caller %q makes no such call — remove the stale entry", key)
	}
}

// classWrite is the per-function result of analyzeClassWrites.
type classWrite struct {
	// writes: the function calls CLI.SetUserClass at least once.
	writes bool
	// resolves: it also calls cli.ResolveLoginClass.
	resolves bool
	// bound: EVERY SetUserClass call receives, as its argument, the identifier
	// that took the resolver's FIRST result. This is the dataflow claim.
	bound bool
	// escapes: SetUserClass is referenced WITHOUT being called (a method value,
	// `f := shell.SetUserClass`). The class write then happens through `f`,
	// where no argument analysis can see it, so the reference is treated as a
	// violation rather than ignored.
	escapes bool
	pos     string
}

// analyzeClassWrites reports, per function in f, how that function writes the
// RBAC login class.
//
// The predicate is DATAFLOW, not co-occurrence. An earlier version asked only
// "does this function mention both names?", which accepted
//
//	_, _ = cli.ResolveLoginClass(login, id) // result discarded
//	shell.SetUserClass("super-user")        // the actual write, unbound
//
// — the resolver called for show and the class supplied from somewhere else,
// which is #6701 with a decoy call in front of it. It also missed
//
//	setClass := shell.SetUserClass
//	setClass("super-user")
//
// entirely, because the write is not a call to a selector named SetUserClass.
// Both are covered now: the first fails `bound`, the second fails `escapes`.
//
// Recognised as bound: `class, reason := cli.ResolveLoginClass(...)` (or the
// package-internal `ResolveLoginClass(...)`) followed by
// `shell.SetUserClass(class)`. Any other argument — a literal, a different
// variable, the blank identifier's neighbour — is unbound. That is deliberately
// strict: an intermediate transformation of the class is exactly the kind of
// re-derivation the canary exists to force into ResolveLoginClass itself.
func analyzeClassWrites(fset *token.FileSet, f *ast.File, pkgRel string) map[string]classWrite {
	out := map[string]classWrite{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		cw := analyzeFuncClassWrite(fn)
		if !cw.writes {
			continue
		}
		if fset != nil {
			cw.pos = fset.Position(fn.Pos()).String()
		}
		out[funcKeyFor(pkgRel, fn)] = cw
	}
	return out
}

// analyzeFuncClassWrite is the single-function half of analyzeClassWrites,
// shared verbatim by the repository walk and the synthetic discriminator tests
// so the proof is of the SAME predicate the walk applies.
func analyzeFuncClassWrite(fn *ast.FuncDecl) classWrite {
	var cw classWrite
	// Identifiers that hold the resolver's first result.
	classVars := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !isResolveLoginClassCall(call) {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
			classVars[id.Name] = true
		}
		return true
	})

	// ast.Inspect descends INTO CallExpr.Fun, so an ordinary
	// `shell.SetUserClass(class)` also yields its own SelectorExpr. Record the
	// selectors that are in call position so the method-VALUE check below sees
	// only genuine unattached references.
	calledFuns := map[ast.Expr]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			calledFuns[call.Fun] = true
		}
		return true
	})

	allBound := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if isResolveLoginClassCall(node) {
				cw.resolves = true
			}
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SetUserClass" {
				return true
			}
			cw.writes = true
			if len(node.Args) != 1 {
				allBound = false
				return true
			}
			arg, ok := node.Args[0].(*ast.Ident)
			if !ok || !classVars[arg.Name] {
				allBound = false
			}
		case *ast.SelectorExpr:
			// A SetUserClass selector that is NOT some call's Fun is a method
			// VALUE: the write happens later through the resulting func value,
			// where no argument analysis can follow it.
			if node.Sel.Name == "SetUserClass" && !calledFuns[node] {
				cw.writes = true
				cw.escapes = true
			}
		}
		return true
	})
	cw.bound = allBound
	return cw
}

// isResolveLoginClassCall matches both `cli.ResolveLoginClass(...)` and the
// package-internal bare `ResolveLoginClass(...)`.
func isResolveLoginClassCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fun.Sel.Name == "ResolveLoginClass"
	case *ast.Ident:
		return fun.Name == "ResolveLoginClass"
	}
	return false
}

// TestSetUserClassCallersResolveThroughTheSharedResolver_6701 binds every RBAC
// class WRITE to the shared resolver's RETURN VALUE, structurally (#6701
// MINOR-2, tightened for the #6706 review MINOR-4).
//
// The sibling canary above bounds WHO may call SetUserClass. That is necessary
// and not sufficient: the one allowlisted caller could stop calling
// cli.ResolveLoginClass and inline a faithful copy of the resolution logic
// instead. Every behavioural test would still pass — an equivalent copy is
// equivalent, and this was measured, not assumed: mutation M15 inlined exactly
// such a copy into applyCLILoginClass and the WHOLE suite stayed green. The
// policy would then be defined in two places, and the next hardening of
// ResolveLoginClass (a new fail-closed branch, a changed root default) would
// reach only one of them.
//
// What it checks, exactly: for every production function that writes the class,
// (a) it calls ResolveLoginClass, (b) every SetUserClass call takes the
// identifier that received that call's first result, and (c) SetUserClass is
// never referenced as a method value, which would move the write out of view.
//
// This is the same structural binding as pkg/osident's adoption canary, one
// layer up: there the shared thing is the IDENTITY, here it is the POLICY that
// maps that identity onto a class.
//
// FAIL-ON-REVERT: replace the ResolveLoginClass call in applyCLILoginClass with
// an inline equivalent, discard its result and pass a literal, or take a method
// value of SetUserClass — each names the function and goes RED, while the
// behavioural tests stay green.
func TestSetUserClassCallersResolveThroughTheSharedResolver_6701(t *testing.T) {
	writers := map[string]classWrite{}
	var filesScanned int

	for _, root := range productionRoots(t) {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				if path != root && skipCanaryDir(d.Name()) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			filesScanned++
			for key, cw := range analyzeClassWrites(fset, f, pkgRelKeyFor(path)) {
				writers[key] = cw
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	if filesScanned == 0 {
		t.Fatal("scanned no production files — the walk is not reaching the source it checks")
	}
	if len(writers) == 0 {
		t.Fatal("found no production caller of SetUserClass at all — the walk is not reaching " +
			"the source it claims to check")
	}

	var offenders []string
	for key, cw := range writers {
		switch {
		case cw.escapes:
			offenders = append(offenders, key+" ("+cw.pos+
				"): takes a METHOD VALUE of SetUserClass, so the class write escapes this check")
		case !cw.resolves:
			offenders = append(offenders, key+" ("+cw.pos+
				"): never calls cli.ResolveLoginClass")
		case !cw.bound:
			offenders = append(offenders, key+" ("+cw.pos+
				"): calls SetUserClass with something other than the resolver's result")
		}
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s — the class written must be the VALUE cli.ResolveLoginClass returned, not "+
			"an independently derived one (#6701)", o)
	}
}

// TestSharedResolverCanaryBindsDataflowNotCoOccurrence_6701 proves the
// predicate discriminates, which is the entire reason it is structural.
//
// It runs the SAME analyzer over a set of functions that are deliberately hard
// to tell apart by name-mention alone, and requires exactly the correct one to
// be accepted. The two evasion cases are the ones the #6706 review demonstrated
// against the previous co-occurrence predicate.
func TestSharedResolverCanaryBindsDataflowNotCoOccurrence_6701(t *testing.T) {
	const src = `package p

func shared(shell userClassSetter, login *L, id I) {
	class, _ := cli.ResolveLoginClass(login, id)
	shell.SetUserClass(class)
}

func inlinedCopy(shell userClassSetter, login *L, id I) {
	class := "unauthorized"
	for _, u := range login.Users {
		if u != nil && u.Name == id.Name && u.Class != "" {
			class = u.Class
		}
	}
	if id.UID == 0 && class == "unauthorized" {
		class = "super-user"
	}
	shell.SetUserClass(class)
}

func decoyCall(shell userClassSetter, login *L, id I) {
	_, _ = cli.ResolveLoginClass(login, id)
	shell.SetUserClass("super-user")
}

func methodValue(shell userClassSetter, login *L, id I) {
	class, _ := cli.ResolveLoginClass(login, id)
	_ = class
	setClass := shell.SetUserClass
	setClass("super-user")
}

func reDerived(shell userClassSetter, login *L, id I) {
	class, _ := cli.ResolveLoginClass(login, id)
	promoted := class
	if id.UID != 0 {
		promoted = "super-user"
	}
	shell.SetUserClass(promoted)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	got := analyzeClassWrites(fset, f, "p")

	type want struct {
		accepted bool
		why      string
	}
	cases := map[string]want{
		"p::shared":      {true, "delegates to the shared resolver and writes its result"},
		"p::inlinedCopy": {false, "inlines a behaviourally identical copy of the policy"},
		"p::decoyCall":   {false, "calls the resolver, DISCARDS it, and writes a literal"},
		"p::methodValue": {false, "writes through a method value the analysis cannot follow"},
		"p::reDerived":   {false, "re-derives the class after the resolver returned"},
	}
	if len(got) != len(cases) {
		t.Fatalf("analyzer saw %d class writers, want %d: %v", len(got), len(cases), got)
	}
	for key, w := range cases {
		cw, ok := got[key]
		if !ok {
			t.Fatalf("analyzer did not classify %s as a class writer at all", key)
		}
		accepted := cw.resolves && cw.bound && !cw.escapes
		if accepted != w.accepted {
			t.Errorf("%s accepted = %v, want %v — %s (analysis: resolves=%v bound=%v escapes=%v)",
				key, accepted, w.accepted, w.why, cw.resolves, cw.bound, cw.escapes)
		}
	}
}

// pkgRelKeyFor turns a walked path into the package-relative key segment:
// "../daemon/cli_rbac.go" -> "daemon", "../../cmd/cli/main.go" -> "cli".
func pkgRelKeyFor(path string) string {
	return filepath.Base(filepath.Dir(path))
}

// funcKeyFor formats the receiver-aware allowlist key for a FuncDecl.
func funcKeyFor(pkgRel string, fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		if recv := recvTypeNameFor(fn.Recv.List[0].Type); recv != "" {
			return pkgRel + "::" + recv + "." + fn.Name.Name
		}
	}
	return pkgRel + "::" + fn.Name.Name
}

// recvTypeNameFor extracts the receiver type name, stripping a leading '*'.
func recvTypeNameFor(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return recvTypeNameFor(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvTypeNameFor(t.X)
	case *ast.IndexListExpr:
		return recvTypeNameFor(t.X)
	}
	return ""
}

// TestSetUserClassCanaryDetectsAnUnallowlistedCaller_6701 proves the walker
// above is not vacuous: it runs the same predicate over a synthetic file that
// reintroduces the #6701 default and requires a hit outside the allowlist.
func TestSetUserClassCanaryDetectsAnUnallowlistedCaller_6701(t *testing.T) {
	const src = `package rogue

func boot(shell interface{ SetUserClass(string) }) {
	shell.SetUserClass("super-user")
}

func viaMethodValue(shell interface{ SetUserClass(string) }) {
	setClass := shell.SetUserClass
	setClass("super-user")
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	var hits []string
	var enclosing string
	ast.Inspect(f, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			enclosing = funcKeyFor("rogue", fn)
			return true
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "SetUserClass" {
			return true
		}
		if _, allowed := allowedSetUserClassCallers[enclosing]; !allowed {
			hits = append(hits, enclosing)
		}
		return true
	})
	sort.Strings(hits)
	want := []string{"rogue::boot", "rogue::viaMethodValue"}
	if len(hits) != len(want) {
		t.Fatalf("synthetic detector found %v, want %v — the canary predicate does not detect "+
			"the defect it claims to guard", hits, want)
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Fatalf("synthetic detector found %v, want %v", hits, want)
		}
	}
}

// productionRoots is the walk root for the #6701 structural canaries: the
// REPOSITORY ROOT, not pkg/ + cmd/.
//
// The previous roots meant a new top-level production package — `internal/`,
// `agent/`, anything a future layout adds — was never scanned, so a
// SetUserClass call there was invisible to both canaries (#6706 MINOR-4). The
// go.mod check makes a wrong relative path a loud failure rather than a silent
// empty walk.
func productionRoots(t *testing.T) []string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root %q has no go.mod (%v) — the canary walk root is wrong and "+
			"would scan nothing", root, err)
	}
	return []string{root}
}

// skipCanaryDir reports directories the canary walks must not descend into:
// every dotted directory (.git, .github, and any tooling scratch or nested
// worktree an agent leaves behind), plus the usual vendored/generated trees.
func skipCanaryDir(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch name {
	case "vendor", "testdata", "node_modules":
		return true
	}
	return false
}
