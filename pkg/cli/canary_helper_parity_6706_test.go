package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// canaryTraversalHelpers are the declarations pkg/cli and pkg/osident must hold
// VERBATIM copies of.
//
// They are duplicated because the two canaries live in different packages and
// neither can import the other's test code. Duplication is the cost; drift is
// the hazard, and it is not hypothetical — every traversal defect this PR has
// had (an invented `node_modules` skip, a `vendor` skip that pruned the
// directory's own files, a build context that answered for the developer's
// machine instead of the appliance) existed in BOTH copies, and a fix applied
// to one would have left the other silently scanning a different file set while
// its comment claimed otherwise.
var canaryTraversalHelpers = []string{
	"walkCanaryFiles",
	"skipCanaryDir",
	"isNestedModuleRoot",
	"compiledByGoBuild",
	"compiledFilesInDir",
	"rebaseCanaryPath",
	"canaryBuildCtxs",
}

// TestCanaryTraversalHelpersMatchTheOsidentCopy_6706 requires the shared
// traversal helpers to be byte-identical between this file and pkg/osident's.
//
// WHAT THIS BUYS. pkg/osident's copies are bound to the toolchain by
// TestCanaryWalkRuleMatchesTheToolchain_6706, which drives walkCanaryFiles over
// a fixture tree and cross-checks the result against `go list ./...` under both
// cgo settings. That proof reaches this package's copies only while they are
// the same code. This test is the link: fix one copy and not the other and it
// reds by declaration name, naming both files.
//
// It compares the declaration SOURCE, from Pos() to End(). Both FuncDecl.Pos()
// and GenDecl.Pos() start at the keyword rather than at the doc comment, so the
// per-package doc comments (which legitimately differ — one holds the
// reasoning, the other points at it) are excluded while every byte of the code
// and its interior comments is compared.
func TestCanaryTraversalHelpersMatchTheOsidentCopy_6706(t *testing.T) {
	const (
		here  = "userclass_entrypoint_canary_test.go"
		there = "../osident/user_env_canary_test.go"
	)
	mine := declSources(t, here)
	theirs := declSources(t, there)

	for _, name := range canaryTraversalHelpers {
		a, okA := mine[name]
		b, okB := theirs[name]
		switch {
		case !okA:
			t.Errorf("%s declares no %s — the shared traversal rule is not in this copy at all",
				here, name)
		case !okB:
			t.Errorf("%s declares no %s — pkg/osident's copy is where the rule is proven against "+
				"the toolchain; without it this package's copy is proven by nothing", there, name)
		case a != b:
			t.Errorf("%s has DRIFTED between %s and %s. The two canaries would then scan "+
				"different file sets while both comments claim cmd/go's rule.\n"+
				"--- %s ---\n%s\n--- %s ---\n%s", name, here, there, here, a, there, b)
		}
	}
}

// declSources maps top-level declaration name -> its source text, for the
// declaration forms the helper list uses (functions and single-name vars).
func declSources(t *testing.T, path string) map[string]string {
	t.Helper()
	src, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	base := fset.File(f.Pos()).Base()
	text := func(n ast.Node) string {
		return string(src[int(n.Pos())-base : int(n.End())-base])
	}

	out := map[string]string{}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				out[d.Name.Name] = text(d)
			}
		case *ast.GenDecl:
			if d.Tok != token.VAR && d.Tok != token.CONST {
				continue
			}
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 {
					continue
				}
				// Only single-spec declarations get the whole GenDecl's text;
				// a grouped `var ( ... )` would compare unrelated neighbours.
				if len(d.Specs) == 1 {
					out[vs.Names[0].Name] = text(d)
				} else {
					out[vs.Names[0].Name] = text(vs)
				}
			}
		}
	}
	return out
}
