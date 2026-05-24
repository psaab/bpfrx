package userspace

import (
	"go/ast"
	"go/parser"
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

	compileSrc := goFunctionSource(t, "manager.go", "Compile")
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

	loaderSrc := goFunctionSource(t, filepath.Join("..", "loader_ebpf.go"), "loadUserspaceShimObjectsOnce")
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
	start := fset.Position(fn.Pos()).Offset
	end := fset.Position(fn.End()).Offset
	return string(data[start:end])
}
