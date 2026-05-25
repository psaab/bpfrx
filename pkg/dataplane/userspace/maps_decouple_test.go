// Package userspace regression canaries for the map-name registry (#1521).
//
// Two canaries enforce the decoupling:
//
//  1. TestNoLiteralMapNamesOutsideRegistry — AST-semantic check that
//     no .Map(<basic string literal>) call inside this package uses a
//     "userspace_" literal outside maps.go. Catches both interpreted
//     and raw string literals. Operator-facing log prose remains free
//     to mention map names by literal (errors.New, fmt.Errorf,
//     comments) because those are not .Map() call arguments.
//
//  2. TestRegistryParityWithLegacyLoader — short-lived consistency
//     canary that pins the registry constants against the literal map
//     names used by the legacy loader at pkg/dataplane/loader_ebpf.go.
//     Self-retires when the loader is deleted by #1476.
package userspace

import (
	"bytes"
	"errors"
	"fmt"
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

// TestNoLiteralMapNamesOutsideRegistry enforces that no .Map() call
// in the userspace package uses a string literal that starts with
// "userspace_" — every such name must be a constant defined in
// maps.go (or named in another go file by symbol).
//
// Rationale (#1521 / Codex r1 HIGH-2 / AGY r1):
//   - Uses go/ast so it inspects actual call expressions, not text.
//   - strconv.Unquote handles both `"userspace_x"` and `\`userspace_x\``.
//   - Skips _test.go files (cap test asserts the literal value of the
//     pinned compatibility name; that's a legitimate test-only use).
//   - Hard-fails on any parse or read error rather than silently
//     swallowing them.
func TestNoLiteralMapNamesOutsideRegistry(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse pkg/dataplane/userspace: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("no Go packages found in current dir")
	}

	var violations []string
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			base := filepath.Base(path)
			if base == "maps.go" {
				// Registry is allowed to hold the literals.
				continue
			}
			if strings.HasSuffix(base, "_test.go") {
				// Test files may reference literal values for clarity
				// (e.g. maps_sync_cap_test.go's pinned-compat assertion).
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel == nil || sel.Sel.Name != "Map" {
					return true
				}
				if len(call.Args) != 1 {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				if !strings.HasPrefix(s, "userspace_") {
					return true
				}
				pos := fset.Position(lit.Pos())
				violations = append(violations, fmt.Sprintf(
					"%s:%d: forbidden literal map name %q in .Map() call — "+
						"add a constant to maps.go and reference it instead",
					pos.Filename, pos.Line, s))
				return true
			})
		}
	}
	if len(violations) > 0 {
		t.Fatalf("AST canary violations:\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestRegistryParityWithLegacyLoader asserts that every userspace
// map-name constant matches a literal string still present in the
// legacy loader at pkg/dataplane/loader_ebpf.go. The two sides
// duplicate the names during the #1476 retirement window; this
// canary keeps them in lockstep so a rename in either file is caught
// at test time, not at helper bringup.
//
// The test Skips when the loader is absent (i.e. #1476 has deleted
// it), so it self-retires cleanly.
func TestRegistryParityWithLegacyLoader(t *testing.T) {
	t.Parallel()

	loaderPath := filepath.Join("..", "loader_ebpf.go")
	body, err := os.ReadFile(loaderPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.Skipf("legacy loader absent (#1476 retirement?): %v", err)
			return
		}
		t.Fatalf("read legacy loader %s: %v", loaderPath, err)
	}

	for _, tc := range []struct {
		name  string
		value string
	}{
		{"mapNameUserspaceCtrl", mapNameUserspaceCtrl},
		{"mapNameUserspaceBindings", mapNameUserspaceBindings},
		{"mapNameUserspaceHeartbeat", mapNameUserspaceHeartbeat},
		{"mapNameUserspaceXSK", mapNameUserspaceXSK},
		{"mapNameUserspaceCPUMap", mapNameUserspaceCPUMap},
		{"mapNameUserspaceSessions", mapNameUserspaceSessions},
		{"mapNameUserspaceIngressIfaces", mapNameUserspaceIngressIfaces},
		{"mapNameUserspaceLocalV4", mapNameUserspaceLocalV4},
		{"mapNameUserspaceLocalV6", mapNameUserspaceLocalV6},
		{"mapNameUserspaceInterfaceNATv4", mapNameUserspaceInterfaceNATv4},
		{"mapNameUserspaceInterfaceNATv6", mapNameUserspaceInterfaceNATv6},
		{"mapNameUserspaceShimDegradedStats", mapNameUserspaceShimDegradedStats},
	} {
		quoted := []byte(`"` + tc.value + `"`)
		if !bytes.Contains(body, quoted) {
			t.Errorf(
				"%s = %q not found as a quoted literal in %s — "+
					"parity broken: rename both sides together or update this canary",
				tc.name, tc.value, loaderPath)
		}
	}
}
