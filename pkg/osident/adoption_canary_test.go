package osident

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

// identitySites are the packages that must derive the invoking identity by
// CALLING osident.Current(), keyed by directory relative to this package.
//
// These are the three #6701 sites. The key is a DIRECTORY, not a file and not a
// line, so moving the call between files inside a package (or renaming the
// enclosing function) does not break the canary — only removing it from the
// package does. Adding a fourth identity site means adding a row here.
var identitySites = map[string]string{
	filepath.Join("..", "cli"):           "pkg/cli — the in-process shell prompt (cli.go New)",
	filepath.Join("..", "daemon"):        "pkg/daemon — the RBAC login class (cli_rbac.go applyCLILoginClass)",
	filepath.Join("..", "..", "cmd/cli"): "cmd/cli — the remote client prompt (main.go resolveUsername)",
}

// callsOsidentCurrent reports whether any non-test .go file directly under dir
// contains a call to osident.Current(). It does NOT recurse: each site is one
// package, and a call in some unrelated nested package would be a false pass.
func callsOsidentCurrent(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			continue
		}
		if fileCallsOsidentCurrent(f) {
			return true, nil
		}
	}
	return false, nil
}

// fileCallsOsidentCurrent is the STRUCTURAL predicate: an `osident.Current()`
// call expression. It is deliberately not a behaviour comparison — a package
// that duplicated Current()'s body inline would produce identical results for
// every input and pass any output-equality test, while silently forking the
// definition of "who is the caller". Only the call itself proves sharing.
func fileCallsOsidentCurrent(f *ast.File) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "osident" || sel.Sel.Name != "Current" {
			return true
		}
		found = true
		return false
	})
	return found
}

// TestIdentitySitesCallOsidentCurrent_6701 binds the three #6701 sites to the
// SHARED identity resolver structurally.
//
// The sibling canary (TestNoIdentityFromEnvironment_6701) proves no site reads
// `$USER`. That is necessary but not sufficient: a site could stop reading
// `$USER` and start reading its own inline `os.Getuid()` + `user.LookupId(...)`
// copy. Every behavioural test would still pass — an equivalent copy is
// equivalent — while the definition of "the caller's identity" quietly forked,
// so a later hardening of osident.Current (say, rejecting a uid with no passwd
// entry differently) would reach two of three sites.
//
// FAIL-ON-REVERT: replace `osident.Current()` at any site with an inline
// equivalent and this test names that site and goes RED, even though the
// program still behaves identically.
func TestIdentitySitesCallOsidentCurrent_6701(t *testing.T) {
	var missing []string
	for dir, desc := range identitySites {
		ok, err := callsOsidentCurrent(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		if !ok {
			missing = append(missing, desc+" (dir "+dir+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("no osident.Current() call found in %s — the identity source must be the SHARED "+
			"resolver, not an inline equivalent (#6701)", m)
	}
}

// TestIdentityAdoptionCanaryDistinguishesSharingFromACopy_6701 proves the
// predicate above actually discriminates, which is the whole point of using a
// structural check instead of a behavioural one.
//
// It runs the predicate over two synthetic files that are BEHAVIOURALLY
// IDENTICAL — one calls the shared resolver, the other inlines an equivalent
// body — and requires exactly one hit. Without this, a predicate that matched
// nothing (or everything) would leave the canary reporting PASS forever.
func TestIdentityAdoptionCanaryDistinguishesSharingFromACopy_6701(t *testing.T) {
	const shared = `package p

import "github.com/psaab/xpf/pkg/osident"

func who() string { return osident.Current().String() }
`
	// Behaviourally equivalent to the above for every input, and exactly what a
	// well-meaning refactor that "removed the dependency" would leave behind.
	const equivalentCopy = `package p

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

func who() string {
	uid := os.Getuid()
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u != nil {
		return u.Username
	}
	return fmt.Sprintf("uid-%d", uid)
}
`
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		{"shared resolver", shared, true},
		{"behaviourally equivalent inline copy", equivalentCopy, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "synthetic.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := fileCallsOsidentCurrent(f); got != tc.want {
				t.Fatalf("fileCallsOsidentCurrent() = %v, want %v — the adoption canary cannot "+
					"tell a shared call from an equivalent copy, so it binds nothing", got, tc.want)
			}
		})
	}
}
