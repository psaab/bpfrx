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
