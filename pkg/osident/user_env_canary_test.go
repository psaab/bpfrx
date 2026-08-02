package osident

import (
	"go/ast"
	"go/build"
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
// Scope: every non-test .go file in the REPOSITORY that the toolchain compiles
// for the host GOOS/GOARCH under EITHER cgo setting — the appliance's
// `CGO_ENABLED=0` and a cgo-enabled developer build; see canaryBuildCtxs for
// why one setting is not enough. Walked from the module root rather than from
// pkg/ + cmd/ (#6706 MINOR-4 — a future top-level production package,
// `internal/` or anything else a layout change adds, was previously outside the
// walk and could read $USER unobserved).
//
// The allowlist is EMPTY and is meant to stay that way — pkg/osident.Current()
// is the one supported way to answer "who is running this", and it reads the
// kernel credential. os.Getenv for anything that is not an identity (XPF_*,
// PATH, TMPDIR, ...) is untouched: the check keys on the argument literal.
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
	scanned := map[string]bool{}
	var hits []identityEnvHit

	for _, root := range roots {
		err := walkCanaryFiles(root, func(path string) {
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return // not our business to police unparsable files
			}
			filesScanned++
			if rel, relErr := filepath.Rel(root, path); relErr == nil {
				scanned[filepath.ToSlash(rel)] = true
			}
			hits = append(hits, identityEnvHits(fset, f)...)
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	for _, want := range traversalSentinels {
		if !scanned[want] {
			t.Fatalf("the walk never scanned %s (it scanned %d files) — a canary that does not "+
				"reach the #6701 defect sites reports nothing about them", want, filesScanned)
		}
	}

	if len(hits) > 0 {
		for _, h := range hits {
			t.Errorf("%s: reads os.Getenv(%q) — identity must come from osident.Current() "+
				"(real uid -> passwd), never from the caller's environment (#6701)", h.pos, h.env)
		}
	}
}

// traversalSentinels are repository-relative files the walk MUST have scanned.
//
// They are not a sample: they are the three #6701 defect sites plus this
// package, i.e. exactly the files whose silence the canary's green result is
// taken to mean something about.
//
// This exists because the previous head asserted only `filesScanned == 0`, and
// claimed in a comment that a wrong root or a wrong suffix filter was "caught by
// the filesScanned == 0 Fatal". Both halves were false (#6706 review r5 F8): a
// wrong root is caught EARLIER, by the go.mod Fatal above; a wrong suffix filter
// (`.go` -> `t.go`) leaves filesScanned in the hundreds, and a PARTIAL directory
// skip — adding "daemon" to skipCanaryDir with a live os.Getenv("USER") planted
// in pkg/daemon — left the Fatal inert and BOTH tests green. A total-wipeout
// floor cannot bind a partial traversal defect; naming the files can.
var traversalSentinels = []string{
	"pkg/daemon/daemon_run.go", // #6701 site 1: the RBAC class
	"pkg/cli/cli.go",           // #6701 site 2: the shell prompt
	"cmd/cli/main.go",          // #6701 site 3: the remote prompt
	"pkg/osident/osident.go",   // the replacement identity source
}

// walkCanaryFiles is THE traversal rule shared by every #6701 structural
// canary: it calls visit with each non-test .go file under root that the
// toolchain compiles, applying cmd/go's directory rule (skipCanaryDir), its
// module boundary (isNestedModuleRoot) and its file rule (compiledByGoBuild).
//
// It is one function rather than a copy per test for the reason #6706 MINOR-3
// established for identityEnvHits: a traversal re-implemented beside the thing
// that tests it proves nothing about the thing under test.
// TestCanaryWalkRuleMatchesTheToolchain_6706 drives THIS function over a
// fixture tree and cross-checks its answer against `go list ./...`.
func walkCanaryFiles(root string, visit func(path string)) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipCanaryDir(root, path) {
				return fs.SkipDir
			}
			// Skip NESTED GO MODULES — a directory below the root carrying its
			// own go.mod FILE. See isNestedModuleRoot for why the
			// file-vs-directory distinction is load-bearing rather than
			// pedantic.
			if path != root && isNestedModuleRoot(path) {
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
		visit(path)
		return nil
	})
}

// skipCanaryDir reports directories the walk must not descend into, modelling
// cmd/go's own directory rule INCLUDING the part of it that is two-phase.
//
// modload/search.go (go1.26.4) does two DIFFERENT things:
//
//   - `.`-prefixed, `_`-prefixed and `testdata` directories set `want = false`
//     (:105-106), which returns filepath.SkipDir at :129-131, BEFORE the
//     directory is added as a package. Nothing in them is compiled.
//   - a `vendor` directory is added as a package FIRST (`isMatch(name)` ->
//     `addPkg(name)`, :139-148) and only THEN has its SUBTREE pruned
//     (`elem == "vendor" ... return filepath.SkipDir`, :150-152). Its own files
//     ARE compiled.
//
// The previous revision returned true for the name "vendor", which skipped the
// directory before reading its files — the same defect shape as the invented
// `node_modules` skip it replaced, in the other direction. Demonstrated at that
// head with `pkg/vendor/zzprobe.go` (`package vendor`) carrying both defect
// shapes: `go list ./...` reported `github.com/psaab/xpf/pkg/vendor`, build and
// vet were rc 0, and all three canaries were green (#6706 review r7 F2). The
// node_modules half is the earlier finding (#6706 review r5 F1), reproduced the
// same way.
//
// So the vendor rule is expressed on the PATH, not the name: descend into a
// `vendor` directory, and skip every directory whose parent is one. Walking
// top-down, skipping vendor's immediate subdirectories makes its whole subtree
// unreachable, which is what pruning it means.
//
// Left in the SAFE (over-scan) direction and deliberately not implemented:
// go.mod `ignore` directives (search.go:107-112) also set `want = false`. There
// are none in this module; if one is added, this walk scans a tree cmd/go does
// not, which reds rather than falls silent.
func skipCanaryDir(root, path string) bool {
	if path == root {
		return false
	}
	name := filepath.Base(path)
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" {
		return true
	}
	parent := filepath.Dir(path)
	return parent != root && filepath.Base(parent) == "vendor"
}

// canaryBuildCtxs are the build contexts a file is offered to. A file is
// scanned if EITHER of them compiles it.
//
// WHY NOT build.Default ALONE. build.Default.CgoEnabled is the AMBIENT
// CGO_ENABLED of the `go test` process — 1 on any machine with a C compiler.
// The shipped binaries are pinned the other way: Makefile:37 and :41 both build
// with `CGO_ENABLED=0`, and osident.go:26-28,41-46,60-66 plus
// docs/system-login.md:161,180 each rest an argument on that. So under
// build.Default a production file carrying `//go:build !cgo` is compiled into
// xpfd and cli and excluded from every #6701 canary. Demonstrated with
// pkg/daemon/zz_nocgo_probe.go carrying both defect shapes: `CGO_ENABLED=0 go
// list` named it, build and vet were rc 0 under BOTH settings, and all three
// canaries were green under the ambient one (#6706 review r7 F1). Worse, the
// same tree gave different coverage on different machines — a CI runner with no
// C compiler defaults to CGO_ENABLED=0 and scans a different set — so a green
// run carried no statement about the binary that ships.
//
// WHY THE UNION RATHER THAN PINNING CgoEnabled=false. Pinning covers the
// shipped configuration and makes the answer machine-independent, which is the
// whole of the defect above. The union does that AND covers `//go:build cgo`
// files, which the pin excludes. This canary's remit is explicitly prospective
// ("whether or not anybody remembers to write a test for it"), and a cgo-only
// file that reads $USER is a defect one Makefile edit away from shipping. The
// union's cost is bounded by an invariant that the pin also satisfies:
// everything scanned is compiled by SOME toolchain configuration on this
// GOOS/GOARCH, so it can never produce a red that no `go build` agrees with —
// the property #6706 review r5 F2 established. Today the union changes nothing:
// `grep -rn '^//go:build' --include=*.go` over non-test files returns zero
// lines, so both settings currently scan the identical set.
//
// KNOWN LIMIT, named rather than implied, and now named on the axis that
// matters. The cgo axis IS covered. What is not: GOOS/GOARCH, which stay at
// build.Default's host values, and custom `-tags`. A violation inside a
// `//go:build windows` or `//go:build debuglog` file is not reported — and is
// not in the appliance either, which is linux/amd64 with no custom tags (the
// Makefile's `debug-log` feature is a cargo feature of the Rust helper, not a
// Go build tag). A parse error in the constraint means go/build cannot answer,
// so the file is SCANNED: on an unanswerable question the guard should fire,
// not fall silent.
//
// One MatchFile quirk, stated because it is an over-scan: a file that imports
// "C" matches under BOTH settings (the CgoFiles/IgnoredGoFiles split happens in
// ImportDir, not in MatchFile), so under CGO_ENABLED=0 it is scanned although
// the shipped build ignores it. The invariant holds — CGO_ENABLED=1 does
// compile it — and there are no such files outside test sources.
var canaryBuildCtxs = func() [2]build.Context {
	shipped, devel := build.Default, build.Default
	shipped.CgoEnabled = false // Makefile builds xpfd and cli with CGO_ENABLED=0
	devel.CgoEnabled = true
	return [2]build.Context{shipped, devel}
}()

// compiledByGoBuild reports whether the toolchain would compile path into the
// package in its directory, asking go/build ITSELF rather than restating its
// rule, under either of canaryBuildCtxs.
//
// `./...` excludes more than `_`/`.`-prefixed DIRECTORIES: go/build's matchFile
// also drops `_`/`.`-prefixed FILES, files whose _GOOS/_GOARCH suffix does not
// match, and files whose //go:build constraint is unsatisfied. The previous head
// filtered on the `.go` suffix alone while its comment claimed the canary
// "cannot red on code `go build ./...` never compiles". Both a
// `pkg/osident/_scratch.go` (absent even from go list's IgnoredGoFiles) and a
// `pkg/osident/zz_windows.go` reddened it with build and vet rc 0 — the exact
// false red the directory half of the rule exists to prevent (#6706 review r5
// F2).
func compiledByGoBuild(path string) bool {
	dir, name := filepath.Dir(path), filepath.Base(path)
	for _, ctxt := range canaryBuildCtxs {
		ok, err := ctxt.MatchFile(dir, name)
		if err != nil || ok {
			return true
		}
	}
	return false
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
// What it does and does not cover, stated precisely because two revisions of
// this comment have now claimed more than it checks:
//
//   - It binds the PREDICATE — selectors, literal unquoting, and the
//     identityEnvVars set. Empty that map, or misspell the selectors, and this
//     test reds while the repository walk stays green.
//   - It does NOT bind the walk's TRAVERSAL. That is bound instead by
//     traversalSentinels above, which names the files the walk must reach; a
//     partial directory skip or a broken suffix filter reds there. The previous
//     revision credited the `filesScanned == 0` Fatal with catching a wrong root
//     and a wrong suffix filter, and it caught neither (#6706 review r5 F8).
//   - Swallowed parse errors are caught by nothing, and remain a known gap. It
//     is a self-limiting one: parser.ParseFile is the parser `go build` uses, so
//     a file this walk cannot parse does not compile either.
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
