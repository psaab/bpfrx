package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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
	roots := []string{"..", filepath.Join("..", "..", "cmd")}

	type call struct{ key, pos string }
	var unexpected []call
	seen := map[string]bool{}

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "vendor", "testdata", "node_modules":
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
			pkgRel := pkgRelKeyFor(path)

			var enclosing string
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok {
					enclosing = funcKeyFor(pkgRel, fn)
					return true
				}
				callExpr, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := callExpr.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "SetUserClass" {
					return true
				}
				seen[enclosing] = true
				if _, allowed := allowedSetUserClassCallers[enclosing]; !allowed {
					unexpected = append(unexpected, call{
						key: enclosing,
						pos: fset.Position(callExpr.Pos()).String(),
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

// TestSetUserClassCallersResolveThroughTheSharedResolver_6701 binds every RBAC
// class WRITE to the shared resolver, structurally (#6701 MINOR-2).
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
// This is the same structural binding as pkg/osident's adoption canary, one
// layer up: there the shared thing is the IDENTITY, here it is the POLICY that
// maps that identity onto a class.
//
// FAIL-ON-REVERT: replace the ResolveLoginClass call in applyCLILoginClass with
// an inline equivalent and this test names the function and goes RED, while the
// behavioural tests stay green.
func TestSetUserClassCallersResolveThroughTheSharedResolver_6701(t *testing.T) {
	roots := []string{"..", filepath.Join("..", "..", "cmd")}

	// funcs that call SetUserClass -> whether the SAME function also calls
	// ResolveLoginClass.
	resolves := map[string]bool{}
	positions := map[string]string{}

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "vendor", "testdata", "node_modules":
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
			pkgRel := pkgRelKeyFor(path)
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				key := funcKeyFor(pkgRel, fn)
				var setsClass, resolvesClass bool
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch fun := call.Fun.(type) {
					case *ast.SelectorExpr:
						// `x.SetUserClass(...)` / `cli.ResolveLoginClass(...)`
						if fun.Sel.Name == "SetUserClass" {
							setsClass = true
						}
						if fun.Sel.Name == "ResolveLoginClass" {
							resolvesClass = true
						}
					case *ast.Ident:
						// bare `ResolveLoginClass(...)` from inside package cli
						if fun.Name == "ResolveLoginClass" {
							resolvesClass = true
						}
					}
					return true
				})
				if setsClass {
					resolves[key] = resolvesClass
					positions[key] = fset.Position(fn.Pos()).String()
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	if len(resolves) == 0 {
		t.Fatal("found no production caller of SetUserClass at all — the walk is not reaching " +
			"the source it claims to check")
	}

	var offenders []string
	for key, ok := range resolves {
		if !ok {
			offenders = append(offenders, key+" ("+positions[key]+")")
		}
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s writes an RBAC class but never calls cli.ResolveLoginClass — the class "+
			"policy must come from the SHARED resolver, not an inline equivalent (#6701)", o)
	}
}

// TestSharedResolverCanaryDistinguishesSharingFromACopy_6701 proves the
// predicate above discriminates, which is the entire reason it is structural.
// It runs the same analysis over two BEHAVIOURALLY IDENTICAL functions — one
// delegating to the shared resolver, one inlining an equivalent body — and
// requires exactly the copy to be flagged.
func TestSharedResolverCanaryDistinguishesSharingFromACopy_6701(t *testing.T) {
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
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	got := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var setsClass, resolvesClass bool
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				if fun.Sel.Name == "SetUserClass" {
					setsClass = true
				}
				if fun.Sel.Name == "ResolveLoginClass" {
					resolvesClass = true
				}
			case *ast.Ident:
				if fun.Name == "ResolveLoginClass" {
					resolvesClass = true
				}
			}
			return true
		})
		if setsClass {
			got[fn.Name.Name] = resolvesClass
		}
	}
	if len(got) != 2 {
		t.Fatalf("detector saw %d SetUserClass writers, want 2: %v", len(got), got)
	}
	if !got["shared"] {
		t.Error("the SHARING function was flagged as not resolving — the canary would fire on " +
			"correct code")
	}
	if got["inlinedCopy"] {
		t.Error("the behaviourally identical INLINE COPY was accepted — the canary cannot tell " +
			"sharing from an equivalent copy, so it binds nothing")
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
		callExpr, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := callExpr.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "SetUserClass" {
			return true
		}
		if _, allowed := allowedSetUserClassCallers[enclosing]; !allowed {
			hits = append(hits, enclosing)
		}
		return true
	})
	if len(hits) != 1 || hits[0] != "rogue::boot" {
		t.Fatalf("synthetic detector found %v, want exactly [rogue::boot] — the canary predicate "+
			"does not detect the defect it claims to guard", hits)
	}
}
