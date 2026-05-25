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

	var violations []string
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, path := range files {
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
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		hits, err := findForbiddenMapNameAliases(string(body))
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, h := range hits {
			violations = append(violations, fmt.Sprintf(
				"%s: forbidden map-name literal %q outside maps.go — "+
					"reference a registry constant from maps.go instead",
				path, h))
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

// findForbiddenMapNameAliases is the alias-canary inspector,
// factored out so it can be exercised against synthetic fixtures.
// Returns the set of forbidden literal values discovered in src.
//
// To close the AGY r2 bypass classes:
//
//   - (A) Trailing-space trim bypass (`"userspace_ctrl "` then
//     TrimSpace): inspect the *trimmed* value of every literal, not
//     just the raw value. A literal that, after trimming
//     whitespace/`%` verbs, exactly matches a registered map name is
//     a bypass and reported.
//   - (D) String-concatenation bypass (`"user" + "space_ctrl"`): the
//     compiler folds untyped string + expressions at compile time so
//     neither component basic literal alone starts with "userspace_".
//     We evaluate every *ast.BinaryExpr whose Op is token.ADD and
//     both operands are string constants (recursively) and report
//     the folded value if it starts with "userspace_".
//
// The basic-literal walk is kept as the primary path (covers the
// vast majority of cases), and the two structural walkers above
// catch the residual bypass classes.
func findForbiddenMapNameAliases(src string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var hits []string
	seen := make(map[ast.Node]bool)

	// Track which BasicLit nodes are immediate operands of a
	// string-concatenation we are about to evaluate as a folded
	// whole, so we do not double-report them from the basic walk.
	concatOperand := make(map[ast.Node]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			return true
		}
		if folded, fok := evalStringConcat(bin); fok {
			if strings.HasPrefix(folded, "userspace_") {
				trimmed := strings.Trim(folded, " \t%")
				if !isKnownNonMapUserspaceLiteral(trimmed) {
					hits = append(hits, folded)
				}
			}
			markBasicLitOperands(bin, concatOperand)
			seen[bin] = true
		}
		return true
	})

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if concatOperand[lit] {
			// Already reported as part of a folded concat.
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		// (D) covered by the concat pass above. This pass handles:
		// (A) trimmed-match: a literal padded with whitespace/`%`
		//     verbs that, when trimmed, equals a registered name.
		// Standard: a literal that starts with "userspace_" and
		// contains no whitespace.
		trimmed := strings.Trim(s, " \t%")
		switch {
		case strings.HasPrefix(s, "userspace_") && !strings.ContainsAny(s, " \t"):
			if !isKnownNonMapUserspaceLiteral(s) {
				hits = append(hits, s)
			}
		case strings.HasPrefix(trimmed, "userspace_") && trimmed != s:
			// Padding bypass: only flag if the trimmed value
			// exactly matches a registered map name. This avoids
			// flagging legitimate prose like
			// "update userspace_local_v4 %08x: %w" which trims to
			// "update userspace_local_v4" — does not start with
			// "userspace_" after trim either side.
			if isExactRegistryMapName(trimmed) {
				hits = append(hits, s)
			}
		}
		return true
	})
	_ = seen
	return hits, nil
}

// evalStringConcat folds a `+` BinaryExpr whose operands are all
// string basic literals (recursively through nested +s and
// parentheses). Returns the folded string and true if the whole
// expression evaluates to a static string.
func evalStringConcat(e ast.Expr) (string, bool) {
	switch n := e.(type) {
	case *ast.ParenExpr:
		return evalStringConcat(n.X)
	case *ast.BasicLit:
		if n.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(n.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if n.Op != token.ADD {
			return "", false
		}
		l, lok := evalStringConcat(n.X)
		if !lok {
			return "", false
		}
		r, rok := evalStringConcat(n.Y)
		if !rok {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// markBasicLitOperands walks an expression and marks every
// BasicLit found as a concat-operand so the standard literal walker
// won't double-report it.
func markBasicLitOperands(e ast.Expr, m map[ast.Node]bool) {
	ast.Inspect(e, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok {
			m[lit] = true
		}
		return true
	})
}

// isExactRegistryMapName returns true iff s equals one of the
// twelve registered map-name constant values. The check is exact
// (post-trim semantics handled by the caller).
func isExactRegistryMapName(s string) bool {
	switch s {
	case mapNameUserspaceCtrl,
		mapNameUserspaceBindings,
		mapNameUserspaceHeartbeat,
		mapNameUserspaceXSK,
		mapNameUserspaceCPUMap,
		mapNameUserspaceSessions,
		mapNameUserspaceIngressIfaces,
		mapNameUserspaceLocalV4,
		mapNameUserspaceLocalV6,
		mapNameUserspaceInterfaceNATv4,
		mapNameUserspaceInterfaceNATv6,
		mapNameUserspaceShimDegradedStats:
		return true
	}
	return false
}

// TestAliasCanaryCatchesBypassPatterns proves the alias-canary
// inspector flags const aliases, parenthesized selectors, method
// aliases, programmatic-name format strings, and concatenation
// fragments. Codex r2 LOW-2 asked for a negative fixture.
func TestAliasCanaryCatchesBypassPatterns(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "const_alias",
			src: `package x
const stale = "userspace_ctrl_alias"
func F(m M) { m.Map(stale) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_ctrl_alias"},
		},
		{
			name: "paren_selector",
			src: `package x
func F(m M) { (m.Map)("userspace_paren_alias") }
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_paren_alias"},
		},
		{
			name: "method_alias",
			src: `package x
func F(m M) { f := m.Map; _ = f("userspace_method_alias") }
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_method_alias"},
		},
		{
			name: "format_template_construction",
			src: `package x
import "fmt"
func F(m M, x string) { _ = m.Map(fmt.Sprintf("userspace_%s", x)) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			want: []string{"userspace_%s"},
		},
		{
			name: "string_concatenation_fragment",
			src: `package x
func F(m M) { _ = m.Map("userspace_" + "session") }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r2 (D): "user" + "space_ctrl" folds to
			// "userspace_ctrl"; the concat walker reports the
			// folded value. "userspace_" + "session" folds to
			// "userspace_session" — caught the same way.
			want: []string{"userspace_session"},
		},
		{
			name: "agy_r2_d_full_split_concat",
			src: `package x
const bypass = "user" + "space_ctrl"
func F(m M) { _ = m.Map(bypass) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r2 (D): exact example. Neither component
			// literal alone starts with "userspace_", but the
			// folded value does. Concat walker reports it.
			want: []string{"userspace_ctrl"},
		},
		{
			name: "agy_r2_a_trim_padded_literal",
			src: `package x
const bypass = "userspace_ctrl "
func F(m M) { _ = m.Map(bypass) } // caller would do TrimSpace
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r2 (A): a literal padded with a trailing space
			// (would slip past the no-whitespace rule), but the
			// trimmed value exactly matches a registered name.
			want: []string{"userspace_ctrl "},
		},
		{
			name: "operator_log_prose_allowed",
			src: `package x
import "errors"
func F() error { return errors.New("update userspace_local_v4 %08x: %w") }
`,
			want: nil,
		},
		{
			name: "known_non_map_allowed",
			src: `package x
func S() string { return "userspace_compat" }
`,
			want: nil,
		},
		{
			name: "raw_string_literal_caught",
			src: "package x\nfunc F(m M) { _ = m.Map(`userspace_raw_alias`) }\ntype M struct{}\nfunc (M) Map(string) any { return nil }\n",
			want: []string{"userspace_raw_alias"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := findForbiddenMapNameAliases(tc.src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !equalStringSets(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(b))
	for _, s := range b {
		m[s]++
	}
	for _, s := range a {
		if m[s] == 0 {
			return false
		}
		m[s]--
	}
	return true
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
