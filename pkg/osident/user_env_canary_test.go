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
	var hits []identityEnvHit

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
				// Skip directories `./...` itself excludes, so this canary
				// cannot red on code `go build ./...` never compiles — that
				// false red is what #6706 MINOR-7 was about, and an underscore
				// directory reproduced it at the previous head.
				if path != root && strings.HasPrefix(d.Name(), "_") {
					return fs.SkipDir
				}
				// Skip NESTED GO MODULES — a directory below the root carrying
				// its own go.mod FILE. See isNestedModuleRoot for why the
				// file-vs-directory distinction is load-bearing rather than
				// pedantic.
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
			hits = append(hits, identityEnvHits(fset, f)...)
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

// identityEnvHit is one production read of an identity-naming environment
// variable, located for the operator.
type identityEnvHit struct {
	pos string
	env string
}

// identityEnvHits is THE detector. Both the repository walk above and the
// anti-vacuity control below call it, which is the point: an earlier revision
// re-implemented this predicate inline in the control, so breaking the walk's
// copy left the control green and the control proved nothing about the code
// under test (#6706 MINOR-3, demonstrated by mutation).
//
// KNOWN LIMIT, stated rather than implied by silence: the argument must be a
// string LITERAL. `const k = "USER"; os.Getenv(k)` is not detected, nor is
// os.Environ() scanned by hand, nor syscall.Getenv. That is a deliberate
// trade — keying on the literal is what keeps os.Getenv("XPF_*"), PATH and
// TMPDIR out of the result — but it means the headline "at any site" is bounded
// by "written as a literal". A sweep at the current head found zero production
// syscall.Getenv/os.LookupEnv identity reads and three os.Environ() uses, all in
// pkg/upgrade assembling a child process environment, none an identity read.
func identityEnvHits(fset *token.FileSet, f *ast.File) []identityEnvHit {
	var out []identityEnvHit
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
		out = append(out, identityEnvHit{pos: fset.Position(call.Pos()).String(), env: name})
		return true
	})
	return out
}

// TestUserEnvCanaryDetectsAViolation_6701 proves the DETECTOR is not vacuous:
// it runs identityEnvHits — the very function the walk above calls, not a copy
// of it — against a synthetic file that does read os.Getenv("USER"), and
// requires both hits.
//
// What it does and does not cover, stated precisely because an earlier revision
// of this comment claimed more: it binds the PREDICATE (selectors, literal
// unquoting, and the identityEnvVars set — empty that map and this test reds).
// It does NOT bind the walk's traversal. A wrong root or a wrong suffix filter
// is caught by the `filesScanned == 0` Fatal in the test above; swallowed parse
// errors are caught by nothing here, and remain a known gap.
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
	for _, h := range identityEnvHits(fset, f) {
		found = append(found, h.env)
	}
	if len(found) != 2 {
		t.Fatalf("the REAL detector found %v in the synthetic violation, want exactly "+
			"[USER LOGNAME] — identityEnvHits does not detect the defect it claims to guard", found)
	}
}

// isNestedModuleRoot reports whether path is the root of a NESTED Go module —
// a directory carrying its own go.mod FILE.
//
// `go list ./...` does not descend into these, so a file inside one is not a
// package of the module under test and cannot be judged by this canary without
// producing a red that `go build ./...` and `go vet ./...` both disagree with.
// This canary walks the module ROOT (widened from pkg/+cmd/ so a new top-level
// package cannot go unscanned), and that widening is what makes the skip
// necessary.
//
// THE !IsDir() TERM IS LOAD-BEARING, not defensive tidiness. cmd/go's own rule
// (modload/search.go) requires a regular file; a DIRECTORY named `go.mod` is not
// a module marker, so `go list ./...` walks straight through it. Without the
// term, `mkdir -p somepkg/go.mod` makes this canary skip a package the toolchain
// genuinely compiles — a planted os.Getenv("USER") inside it PASSES. Proven by
// mutation: with the term, the planted violation reds by file:line:col; without
// it, green (#6706 MINOR-1).
//
// The trigger was NOT an in-tree checkout, as an earlier revision of this
// comment said. `git ls-files | grep go.mod` returns exactly one line, the
// repository root. The nested module is `wt-master/`, an UNTRACKED agent-scratch
// worktree — which is precisely why the skip must key on the go.mod marker
// rather than on a name a future scratch directory might not use.
//
// Scope limit worth naming: "not in `./...`" is not the same as "does not ship".
// A `replace example.com/nested => ./nested` directive would link a nested
// module into the binary while `go list ./...` still reports zero packages for
// it, so this skip would hide it. Not live today — one tracked go.mod, no
// replace directives — but the reasoning does not extend that far (#6706
// MINOR-2).
func isNestedModuleRoot(path string) bool {
	info, err := os.Stat(filepath.Join(path, "go.mod"))
	return err == nil && !info.IsDir()
}
