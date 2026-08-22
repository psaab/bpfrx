package userspace

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserspaceStartupUsesShimLoaderBoundary(t *testing.T) {
	t.Parallel()

	loadSrc := goFunctionSource(t, "manager.go", "Load")
	if !strings.Contains(loadSrc, "LoadUserspaceShim") {
		t.Fatalf("userspace Load must use LoadUserspaceShim, got:\n%s", loadSrc)
	}
	if strings.Contains(loadSrc, ".Load()") {
		t.Fatalf("userspace Load must not call legacy Manager.Load:\n%s", loadSrc)
	}

	compileSrc := goFunctionSource(t, "manager_compile.go", "Compile")
	if !strings.Contains(compileSrc, "CompileUserspaceShim") {
		t.Fatalf("userspace Compile must use CompileUserspaceShim, got:\n%s", compileSrc)
	}
	if strings.Contains(compileSrc, ".Compile(cfg)") {
		t.Fatalf("userspace Compile must not call legacy Manager.Compile:\n%s", compileSrc)
	}

	adapterLoadSrc := goFunctionSource(t, "legacy_dataplane.go", "Load")
	if !strings.Contains(adapterLoadSrc, "m.Load()") || strings.Contains(adapterLoadSrc, "DataPlane.Load") {
		t.Fatalf("legacy adapter Load must route through userspace Manager.Load:\n%s", adapterLoadSrc)
	}
	adapterCompileSrc := goFunctionSource(t, "legacy_dataplane.go", "Compile")
	if !strings.Contains(adapterCompileSrc, "m.Compile(cfg)") || strings.Contains(adapterCompileSrc, "DataPlane.Compile") {
		t.Fatalf("legacy adapter Compile must route through userspace Manager.Compile:\n%s", adapterCompileSrc)
	}
}

func TestUserspaceShimLoaderDoesNotReferenceLegacyObjects(t *testing.T) {
	t.Parallel()

	// Post-#1476 the retained shim loader graph lives in
	// loader_userspace_shim.go. The pre-#1476 location at
	// `../loader_ebpf.go` is deleted along with the legacy
	// XDP/TC bpf2go batch it used to coexist with.
	loaderSrc := goFunctionSource(t, filepath.Join("..", "loader_userspace_shim.go"), "loadUserspaceShimObjectsOnce")
	if !strings.Contains(loaderSrc, "loadRustUserspaceXDP") {
		t.Fatalf("userspace shim loader must load the retained Rust shim:\n%s", loaderSrc)
	}
	if !strings.Contains(loaderSrc, "userspaceShimEntryProg") {
		t.Fatalf("userspace shim loader must register the explicit shim entry program:\n%s", loaderSrc)
	}
	assertNoLegacyLoaderTokens(t, "loadUserspaceShimObjectsOnce", loaderSrc)

	compileSrc := goFunctionSource(t, filepath.Join("..", "loader.go"), "CompileUserspaceShim")
	assertNoLegacyLoaderTokens(t, "CompileUserspaceShim", compileSrc)
	if strings.Contains(compileSrc, "AttachTC") {
		t.Fatalf("CompileUserspaceShim must not attach TC programs:\n%s", compileSrc)
	}
}

func assertNoLegacyLoaderTokens(t *testing.T, name, src string) {
	t.Helper()
	for _, token := range []string{
		"loadAllObjects",
		"loadXpfXdp",
		"loadXpfTc",
		"xpfXdp",
		"xpfTc",
		"xdp_main_prog",
		"tc_main_prog",
	} {
		if strings.Contains(src, token) {
			t.Fatalf("%s must not reference legacy loader token %q:\n%s", name, token, src)
		}
	}
}

func goFunctionSource(t *testing.T, path, name string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		candidate, ok := decl.(*ast.FuncDecl)
		if !ok || candidate.Name.Name != name {
			continue
		}
		fn = candidate
		break
	}
	if fn == nil {
		t.Fatalf("function %s not found in %s", name, path)
	}
	// RETURN CODE, NOT TEXT (#6647). This used to slice the raw file bytes
	// from fn.Pos() to fn.End(), which includes every comment INSIDE the
	// function body — so a source-scanning guard built on it could be
	// satisfied by a comment that merely quotes the call it demands.
	//
	// MEASURED on this file's own subject before the fix: deleting the real
	// `m.disarmSnapshotProtocolFailClosedLocked(snap, err, samePlanRefresh)`
	// from applyCompiledSnapshot, substituting the weaker plain-disarm call,
	// and leaving the demanded string behind in a `//` comment left
	// TestProtocolGateSitesRouteThroughFailClosedHelper5488 GREEN — and the
	// whole pkg/dataplane/userspace suite green with it, at `go vet` rc 0. The
	// #5488 F7 fail-closed compensation was unpinned in exactly the way the
	// guard existed to prevent.
	//
	// ParseFile ran with mode 0 above, so comments were never attached to the
	// AST; printing the node back out therefore yields the declaration's CODE
	// with every interior comment dropped. Formatting is gofmt-normalised,
	// which is what the tree is already in, so asserted call-expression
	// substrings are unaffected.
	//
	// The direction is right for both assertion shapes every caller uses: a
	// presence check can no longer be faked by a comment, and a banned-token
	// check can no longer FALSE-POSITIVE on prose that names the token it
	// forbids.
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, fn); err != nil {
		t.Fatalf("print %s from %s: %v", name, path, err)
	}
	return buf.String()
}

// #6647: goFunctionSource must return CODE, not raw file text.
//
// Every source-scanning guard in this package is built on it, including the one
// that pins the #5488 F7 fail-closed compensation in applyCompiledSnapshot —
// the compensator that closes #6647's "abort strands an armed helper behind new
// classifier state". While the helper sliced raw bytes from fn.Pos() to
// fn.End(), interior comments came back with the code, so a guard demanding a
// call could be satisfied by a comment that merely quotes it.
//
// MEASURED at origin/master before this fix, on that exact subject: deleting
// `m.disarmSnapshotProtocolFailClosedLocked(snap, err, samePlanRefresh)` from
// applyCompiledSnapshot, substituting the weaker plain-disarm call, and leaving
// the demanded string behind in a `//` comment left
// TestProtocolGateSitesRouteThroughFailClosedHelper5488 GREEN — and the whole
// pkg/dataplane/userspace suite green with it, at `go vet` rc 0.
//
// This cell is the paired proof: the SAME text is present in a comment and
// absent from the code, so a helper that leaks comments returns it and a helper
// that returns code does not. Reverting to the byte-slice form reds it.
func TestGoFunctionSourceReturnsCodeNotComments6647(t *testing.T) {
	t.Parallel()

	// A subject whose body carries a comment naming a call it does NOT make.
	// commentDecoySubject6647 is defined below purely for this cell.
	src := goFunctionSource(t, "shim_loader_boundary_test.go", "commentDecoySubject6647")

	if strings.Contains(src, "decoyCallThatIsOnlyEverMentionedInAComment") {
		t.Fatalf("goFunctionSource leaked an interior comment: the returned text "+
			"contains a call the function never makes, so every presence guard "+
			"built on this helper can be satisfied by a comment quoting the line "+
			"it demands (#6647). Got:\n%s", src)
	}
	// Positive control: the real call in the body must still be visible, or the
	// helper would be "safe" by returning nothing useful and every guard above
	// would pass vacuously.
	if !strings.Contains(src, "realCallTheSubjectActuallyMakes") {
		t.Fatalf("goFunctionSource dropped real code; guards built on it would "+
			"pass vacuously. Got:\n%s", src)
	}
}

func realCallTheSubjectActuallyMakes() int { return 0 }

// commentDecoySubject6647 exists only as the subject of
// TestGoFunctionSourceReturnsCodeNotComments6647.
func commentDecoySubject6647() int {
	// decoyCallThatIsOnlyEverMentionedInAComment() is named here and nowhere
	// else in this function's code. A comment-leaking reader returns it.
	return realCallTheSubjectActuallyMakes()
}
