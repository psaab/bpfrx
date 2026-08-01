package osident

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// identityEnvVars are the environment variables that name the invoking account.
// Reading either of them to decide WHO the caller is was the #6701 defect: they
// are set by the caller's own shell, so `USER=nobody cli` re-identified a
// `class read-only` operator as an unconfigured user, which the old default
// then promoted to super-user.
var identityEnvVars = map[string]bool{
	"USER":    true,
	"LOGNAME": true,
}

// TestNoIdentityFromEnvironment_6701 is the cross-site completeness canary for
// #6701. The defect had THREE call sites — pkg/daemon/daemon_run.go (the RBAC
// class), pkg/cli/cli.go (the shell prompt) and cmd/cli/main.go (the remote
// prompt) — and each per-site test binds only its own site. This one binds the
// PROPERTY across the whole Go tree: no production code may derive an identity
// from `os.Getenv("USER")` / `os.Getenv("LOGNAME")` again, at any site, whether
// or not anybody remembers to write a test for it.
//
// FAIL-ON-REVERT: restore `username := os.Getenv("USER")` at any of the three
// sites (or add a fourth) and this test names the file, line and variable and
// goes RED.
//
// Scope: every non-test .go file in the REPOSITORY, walked from the module
// root rather than from pkg/ + cmd/ (#6706 MINOR-4 — a future top-level
// production package, `internal/` or anything else a layout change adds, was
// previously outside the walk and could read $USER unobserved). The allowlist
// is EMPTY and is meant to stay that way — pkg/osident.Current() is the one
// supported way to answer "who is running this", and it reads the kernel
// credential. os.Getenv for anything that is not an identity (XPF_*, PATH,
// TMPDIR, ...) is untouched: the check keys on the argument literal.
func TestNoIdentityFromEnvironment_6701(t *testing.T) {
	repoRoot, absErr := filepath.Abs(filepath.Join("..", ".."))
	if absErr != nil {
		t.Fatalf("resolve repository root: %v", absErr)
	}
	if _, statErr := os.Stat(filepath.Join(repoRoot, "go.mod")); statErr != nil {
		t.Fatalf("repository root %q has no go.mod (%v) — the canary walk root is wrong and "+
			"would scan nothing", repoRoot, statErr)
	}
	roots := []string{repoRoot}
	var filesScanned int

	type hit struct {
		pos string
		env string
	}
	var hits []hit

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Skip vendored / generated / VCS trees, and every dotted
				// directory (.git, .github, agent scratch, nested worktrees).
				if path != root && strings.HasPrefix(d.Name(), ".") {
					return fs.SkipDir
				}
				// Skip NESTED GO MODULES — a directory below the root carrying
				// its own go.mod. `go build ./...` skips them, so code inside
				// one is not part of the module under test and must not be
				// judged by this canary. Not hypothetical: this repository
				// carries an in-tree checkout with its own go.mod holding the
				// pre-#6701 os.Getenv("USER"), which reddened this canary on
				// code this module never builds.
				if path != root && isNestedModuleRoot(path) {
					return fs.SkipDir
				}
				switch d.Name() {
				case "vendor", "testdata", "node_modules":
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
				return nil // not our business to police unparsable files
			}
			filesScanned++
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "os" {
					return true
				}
				if sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv" {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				name, uerr := strconv.Unquote(lit.Value)
				if uerr != nil || !identityEnvVars[name] {
					return true
				}
				hits = append(hits, hit{pos: fset.Position(call.Pos()).String(), env: name})
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

	if len(hits) > 0 {
		for _, h := range hits {
			t.Errorf("%s: reads os.Getenv(%q) — identity must come from osident.Current() "+
				"(real uid -> passwd), never from the caller's environment (#6701)", h.pos, h.env)
		}
	}
}

// TestUserEnvCanaryDetectsAViolation_6701 proves the canary above is not
// vacuous: it exercises the same AST predicate against a synthetic source file
// that DOES read os.Getenv("USER"), and requires a hit. Without this, a walk
// that silently matched nothing (wrong root, wrong suffix filter, parse errors
// swallowed) would report PASS forever.
func TestUserEnvCanaryDetectsAViolation_6701(t *testing.T) {
	const src = `package p

import "os"

func who() string {
	u := os.Getenv("USER")
	if u == "" {
		u = os.Getenv("LOGNAME")
	}
	_ = os.Getenv("XPF_UNRELATED")
	return u
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "os" {
			return true
		}
		if sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		name, uerr := strconv.Unquote(lit.Value)
		if uerr != nil || !identityEnvVars[name] {
			return true
		}
		found = append(found, name)
		return true
	})
	if len(found) != 2 {
		t.Fatalf("synthetic detector found %v, want exactly [USER LOGNAME] — the canary predicate "+
			"does not actually detect the defect it claims to guard", found)
	}
}

// isNestedModuleRoot reports whether path is the root of a NESTED Go module —
// a directory carrying its own go.mod.
//
// `go build ./...` does not descend into these, so production code inside one is
// not part of the module under test. This canary walks the module ROOT (widened
// from pkg/+cmd/ so a new top-level package cannot go unscanned), and that
// widening is what makes this skip necessary.
//
// Not hypothetical: this repository carries an in-tree checkout with its own
// go.mod holding the pre-#6701 os.Getenv("USER"). Without this skip the canary
// reds on files outside the module under test while build and vet stay clean —
// i.e. `make test` fails for code this module never compiles.
func isNestedModuleRoot(path string) bool {
	_, err := os.Stat(filepath.Join(path, "go.mod"))
	return err == nil
}
