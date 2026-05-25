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

// TestNoMapNameLiteralAliasesOutsideRegistry closes the
// const-alias / parenthesized-selector / method-alias bypasses
// that the .Map()-only canary above does not catch:
//
//	const stale = "userspace_ctrl"
//	m.bpfShim.Map(stale)            // const alias
//	(m.bpfShim.Map)("userspace_ctrl") // parenthesized selector
//	f := m.bpfShim.Map; f("userspace_ctrl") // method alias
//
// All three patterns hide the literal from the .Map(literal)
// inspector. This canary walks every *ast.BasicLit in the package
// (excluding maps.go and _test.go files) and fails on any string
// literal whose entire trimmed value starts with "userspace_" and
// does NOT look like an operator-facing format string. The
// "format-looking" exclusion is conservative: literals containing
// whitespace or a `%` verb are treated as log/error prose and
// permitted.
//
// Rationale: closes Codex code-review r1 MEDIUM-1 and AGY r1 §1
// (const alias / paren selector / method alias).
func TestNoMapNameLiteralAliasesOutsideRegistry(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse pkg/dataplane/userspace: %v", err)
	}

	var violations []string
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			base := filepath.Base(path)
			if base == "maps.go" {
				continue
			}
			if strings.HasSuffix(base, "_test.go") {
				// Test files may construct map-name literals in
				// helpers (e.g. injectShimMap) without functional
				// risk on the production path.
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil || !strings.HasPrefix(s, "userspace_") {
					return true
				}
				// Operator-facing format strings legitimately
				// contain the map name as a substring (e.g.
				// `"update userspace_local_v4 %08x: %w"` or
				// `"userspace_ctrl map not loaded"`). Heuristic:
				// any whitespace or `%` verb signals format
				// prose, not a declaration alias.
				if strings.ContainsAny(s, " \t%") {
					return true
				}
				// Known non-map "userspace_*" identifiers used as
				// operator-facing tokens (mode names, entry-program
				// names, etc.). These predate this canary and are
				// not BPF map names. Extend this list deliberately
				// only when a new such identifier is introduced.
				if isKnownNonMapUserspaceLiteral(s) {
					return true
				}
				pos := fset.Position(lit.Pos())
				violations = append(violations, fmt.Sprintf(
					"%s:%d: forbidden map-name literal %q outside maps.go — "+
						"reference a registry constant from maps.go instead",
					pos.Filename, pos.Line, s))
				return true
			})
		}
	}
	if len(violations) > 0 {
		t.Fatalf("AST alias canary violations:\n  %s", strings.Join(violations, "\n  "))
	}
}

// isKnownNonMapUserspaceLiteral lists "userspace_*" identifiers in
// the package that are NOT BPF map names but operator-facing tokens
// returned from String() helpers or used as JSON field values. They
// pre-date the registry and are intentionally not subject to the
// canary. Extending this list is a conscious decision the reviewer
// should challenge.
func isKnownNonMapUserspaceLiteral(s string) bool {
	switch s {
	case "userspace_compat", // DataplaneMode.String()
		"userspace_strict": // DataplaneMode.String()
		return true
	}
	return false
}

// TestRegistryParityWithLegacyLoader asserts that every userspace
// map-name constant matches a literal string still present in the
// legacy loader at pkg/dataplane/loader_ebpf.go. The two sides
// duplicate the names during the #1476 retirement window; this
// canary keeps them in lockstep so a rename in either file is caught
// at test time, not at helper bringup.
//
// The test self-retires (t.Skip) only when the explicit retirement
// sentinel BPFRX_LEGACY_LOADER_RETIRED=1 is set. Without the
// sentinel, a missing loader_ebpf.go is a hard failure — this is
// deliberate per AGY r1 §2: a sibling PR that *moves* the loader
// (e.g. to pkg/dataplane/ebpf/loader.go) must explicitly accept
// retirement before this canary stands down. Otherwise drift
// protection silently disappears.
func TestRegistryParityWithLegacyLoader(t *testing.T) {
	t.Parallel()

	loaderPath := filepath.Join("..", "loader_ebpf.go")
	body, err := os.ReadFile(loaderPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && os.Getenv("BPFRX_LEGACY_LOADER_RETIRED") == "1" {
			t.Skipf("legacy loader absent and BPFRX_LEGACY_LOADER_RETIRED=1 — #1476 retired: %v", err)
			return
		}
		t.Fatalf("read legacy loader %s: %v "+
			"(if #1476 has retired the loader, set BPFRX_LEGACY_LOADER_RETIRED=1 "+
			"or delete this canary)", loaderPath, err)
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
