package cli

import (
	"go/ast"
	"go/build"
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
	scanned := map[string]bool{}
	var filesScanned int

	for _, root := range productionRoots(t) {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				if path != root && (skipCanaryDir(d.Name()) || isNestedModuleRoot(path)) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if !compiledByGoBuild(path) {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			filesScanned++
			scanned[relKeyFor(root, path)] = true

			for _, ref := range setUserClassRefs(fset, f, pkgRelKeyFor(path)) {
				seen[ref.key] = true
				if _, allowed := allowedSetUserClassCallers[ref.key]; !allowed {
					unexpected = append(unexpected, call{key: ref.key, pos: ref.pos})
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	requireTraversalSentinels(t, scanned, filesScanned)

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

// packageLevelKey is the attribution for a SetUserClass reference that is not
// inside any function — a package-level `var x = shell.SetUserClass`. It is
// deliberately not a valid Go identifier, so it can never collide with a
// funcKeyFor result and can never be spelled in allowedSetUserClassCallers.
const packageLevelKey = "<package-level declaration>"

// classRef is one production reference to SetUserClass, attributed to the
// top-level declaration that encloses it.
type classRef struct{ key, pos string }

// setUserClassRefs is THE allowlist predicate: every SetUserClass reference in
// f, keyed by the TOP-LEVEL DECLARATION that encloses it. Both the repository
// walk and the synthetic controls below call it, so breaking it reds the
// controls rather than leaving them proving something about a copy (the same
// vacuity #6706 MINOR-3 fixed for pkg/osident's canary).
//
// WHY IT ITERATES f.Decls INSTEAD OF TRACKING A RUNNING `enclosing`. The
// previous version set `enclosing` on entering an *ast.FuncDecl during a single
// ast.Inspect over the whole file and NEVER CLEARED IT. ast.Inspect visits
// File.Decls in source order, so a *ast.GenDecl appearing after a FuncDecl was
// attributed to that function. Appending
//
//	var zzRogueSetter = zzRogueShell.SetUserClass
//	func zzBoot() { zzRogueSetter("super-user") }
//
// to pkg/daemon/cli_rbac.go — after the one allowlisted function — inherited the
// key `daemon::applyCLILoginClass` and was SILENTLY ALLOWLISTED: build rc 0, vet
// rc 0, both canaries ok. The identical declaration in a file of its own reds,
// which isolates the cause to the carry-over rather than to the declaration form
// (#6706 review r5 F3). The escape landed in the one file the allowlist exists
// to fence, and the sibling dataflow canary cannot cover for it —
// analyzeClassWrites iterates f.Decls for *ast.FuncDecl only, so a GenDecl is
// invisible to it.
//
// Keying on the enclosing decl makes an unattributed reference unattributable to
// an allowlisted key by construction, rather than by remembering to reset a
// variable.
func setUserClassRefs(fset *token.FileSet, f *ast.File, pkgRel string) []classRef {
	var out []classRef
	for _, decl := range f.Decls {
		key := pkgRel + "::" + packageLevelKey
		if fn, ok := decl.(*ast.FuncDecl); ok {
			key = funcKeyFor(pkgRel, fn)
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			// A SetUserClass selector in ANY position — called, or taken as a
			// method value (`f := shell.SetUserClass`). The method-value form is
			// a class write too, and matching only CallExpr.Fun let it walk
			// straight past this allowlist (#6706 MINOR-4).
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SetUserClass" {
				return true
			}
			out = append(out, classRef{key: key, pos: fset.Position(sel.Pos()).String()})
			return true
		})
	}
	return out
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
// value of SetUserClass INSIDE a function — each names the function and goes
// RED, while the behavioural tests stay green.
//
// One shape this test does NOT catch, named rather than implied: a PACKAGE-LEVEL
// `var f = shell.SetUserClass`. analyzeClassWrites iterates f.Decls for
// *ast.FuncDecl only, so a GenDecl is invisible to it. That escape is caught by
// the sibling allowlist canary above, which attributes such a reference to
// `<pkg>::<package-level declaration>` — a key no allowlist entry can hold. It
// was NOT caught by anything before #6706 review r5 F3.
func TestSetUserClassCallersResolveThroughTheSharedResolver_6701(t *testing.T) {
	writers := map[string]classWrite{}
	scanned := map[string]bool{}
	var filesScanned int

	for _, root := range productionRoots(t) {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				if path != root && (skipCanaryDir(d.Name()) || isNestedModuleRoot(path)) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if !compiledByGoBuild(path) {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			filesScanned++
			scanned[relKeyFor(root, path)] = true
			for key, cw := range analyzeClassWrites(fset, f, pkgRelKeyFor(path)) {
				writers[key] = cw
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	requireTraversalSentinels(t, scanned, filesScanned)
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
// above is not vacuous: it runs setUserClassRefs — the very function the walk
// calls, not a copy of it — over a synthetic file that reintroduces the #6701
// default, and requires a hit outside the allowlist.
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
	for _, ref := range setUserClassRefs(fset, f, "rogue") {
		if _, allowed := allowedSetUserClassCallers[ref.key]; !allowed {
			hits = append(hits, ref.key)
		}
	}
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

// TestPackageLevelClassWriteIsNotAllowlistedByANeighbour_6701 is the regression
// test for the allowlist BYPASS the #6706 r5 review demonstrated (F3).
//
// The synthetic source is the shape that escaped, reduced: the one allowlisted
// function, followed in the SAME FILE by a package-level method value of
// SetUserClass. With the old running-`enclosing` predicate the var inherited
// `daemon::applyCLILoginClass`, matched the allowlist, and was reported by
// nothing — appended to the real pkg/daemon/cli_rbac.go it gave build rc 0, vet
// rc 0 and both canaries ok.
//
// FAIL-ON-REVERT: key setUserClassRefs on a running `enclosing` variable again
// and this reds — the second reference is attributed to the allowlisted function
// instead of to the package level.
func TestPackageLevelClassWriteIsNotAllowlistedByANeighbour_6701(t *testing.T) {
	const src = `package daemon

func applyCLILoginClass(shell userClassSetter, cfg *config.Config, id osident.Identity) {
	class, _ := cli.ResolveLoginClass(cfg.System.Login, id)
	shell.SetUserClass(class)
}

var rogueSetter = rogueShell.SetUserClass

func boot() { rogueSetter("super-user") }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}

	var keys []string
	var unallowlisted []string
	for _, ref := range setUserClassRefs(fset, f, "daemon") {
		keys = append(keys, ref.key)
		if _, allowed := allowedSetUserClassCallers[ref.key]; !allowed {
			unallowlisted = append(unallowlisted, ref.key)
		}
	}
	sort.Strings(keys)

	wantKeys := []string{"daemon::" + packageLevelKey, "daemon::applyCLILoginClass"}
	if len(keys) != len(wantKeys) || keys[0] != wantKeys[0] || keys[1] != wantKeys[1] {
		t.Fatalf("setUserClassRefs attributed %v, want %v — a package-level SetUserClass "+
			"reference must NOT inherit the key of the function declared above it, or the "+
			"allowlist can be bypassed from inside the one file it exists to fence", keys, wantKeys)
	}
	if len(unallowlisted) != 1 || unallowlisted[0] != "daemon::"+packageLevelKey {
		t.Fatalf("unallowlisted references = %v, want exactly [daemon::%s]",
			unallowlisted, packageLevelKey)
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

// isNestedModuleRoot reports whether path is the root of a NESTED Go module —
// a directory carrying its own go.mod FILE.
//
// `go list ./...` does not descend into these, so a file inside one is not a
// package of the module under test and must not be judged by this canary. The
// walk was widened from pkg/+cmd/ to the module root to close a real gap (a new
// top-level package would otherwise go unscanned), and that widening is what
// made this necessary.
//
// THE !IsDir() TERM IS LOAD-BEARING. cmd/go's own rule (modload/search.go)
// requires a regular file, so a DIRECTORY named `go.mod` is not a module marker
// and `go list ./...` walks straight through it. Without the term,
// `mkdir -p somepkg/go.mod` makes this canary skip a package the toolchain
// genuinely compiles, and a planted violation inside it PASSES (#6706 MINOR-1,
// proven by mutation).
//
// The trigger was NOT an in-tree checkout, as an earlier revision of this
// comment said. `git ls-files | grep go.mod` returns exactly one line, the
// repository root; the nested module is `wt-master/`, an UNTRACKED agent-scratch
// worktree. That is why the skip keys on the go.mod marker rather than a name.
//
// Scope limit: "not in `./...`" is not "does not ship" — a `replace` directive
// would link a nested module into the binary while `go list ./...` still reports
// zero packages for it. Not live today (one tracked go.mod, no replace
// directives), but the reasoning does not extend that far (#6706 MINOR-2).
func isNestedModuleRoot(path string) bool {
	info, err := os.Stat(filepath.Join(path, "go.mod"))
	return err == nil && !info.IsDir()
}

// skipCanaryDir reports directories the canary walks must not descend into.
//
// It is EXACTLY cmd/go's own directory rule, and the equality is the point.
// modload/search.go excludes `.`-prefixed, `_`-prefixed and `testdata`
// subdirectories and prunes `vendor` separately; it has no other name-based
// rule, in particular NO `node_modules` rule. Skipping node_modules made a
// package `go build ./...` genuinely compiles invisible to all three #6701
// canaries — demonstrated at the previous head with a file carrying both defect
// shapes, `go list ./...` naming the package and every canary green (#6706
// review r5 F1). Excluding the `_`/`.` trees is the other direction and is
// correct: scanning them produces a red `go build ./...` and `go vet ./...`
// disagree with (#6706 MINOR-7, reproduced with an `_scratch/` directory).
func skipCanaryDir(name string) bool {
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return true
	}
	return name == "vendor" || name == "testdata"
}

// compiledByGoBuild reports whether the toolchain would compile path into the
// package in its directory, asking go/build ITSELF rather than restating its
// rule. Mirrors pkg/osident's copy — see it for why the `.go` suffix test alone
// was not the `./...` rule (#6706 review r5 F2) and for the build-context limit.
func compiledByGoBuild(path string) bool {
	ok, err := build.Default.MatchFile(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return true
	}
	return ok
}

// relKeyFor renders a walked path relative to root with forward slashes.
func relKeyFor(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return ""
	}
	return filepath.ToSlash(rel)
}

// traversalSentinels are repository-relative files both walks MUST have
// scanned: the three #6701 defect sites plus the resolver and its identity
// source. See pkg/osident's copy for why a `filesScanned == 0` floor does not
// bind a PARTIAL traversal defect (#6706 review r5 F8).
//
// The allowlist's own stale-entry check already reds if pkg/daemon goes
// unscanned, since `daemon::applyCLILoginClass` would stop being seen. This is
// the same guarantee for the other three, and it fires with a message that names
// the traversal rather than the allowlist.
var traversalSentinels = []string{
	"pkg/daemon/daemon_run.go",
	"pkg/daemon/cli_rbac.go",
	"pkg/cli/cli.go",
	"pkg/cli/identity.go",
	"cmd/cli/main.go",
}

func requireTraversalSentinels(t *testing.T, scanned map[string]bool, filesScanned int) {
	t.Helper()
	for _, want := range traversalSentinels {
		if !scanned[want] {
			t.Fatalf("the walk never scanned %s (it scanned %d files) — a canary that does not "+
				"reach the #6701 sites reports nothing about them", want, filesScanned)
		}
	}
}
