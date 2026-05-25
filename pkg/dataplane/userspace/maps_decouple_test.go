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
	"unicode"
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

	// Build a const-identifier symbol table by walking every
	// top-level const decl. Values that are themselves foldable
	// string expressions get a fully-resolved string. Identifiers
	// in initializers are resolved against the partial table
	// (Go forbids forward references between top-level consts so
	// the source order is a topological order; walking decls in
	// file order is sufficient).
	consts := map[string]string{}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if v, ok := evalStringExpr(vs.Values[i], consts); ok {
					consts[name.Name] = v
				}
			}
		}
	}

	// Track which AST nodes have already been reported as part of
	// a folded concat so the basic-literal walk does not double-
	// report.
	concatOperand := map[ast.Node]bool{}

	hitSet := map[string]struct{}{}
	report := func(s string) {
		// Permitted: known non-map operator-facing tokens, and
		// the registry-internal exact strings (those are flagged
		// only when they appear OUTSIDE maps.go; this helper has
		// no visibility into file boundaries, so the file-walker
		// caller already excludes maps.go).
		if isKnownNonMapUserspaceLiteral(s) {
			return
		}
		hitSet[s] = struct{}{}
	}

	// Pass 1: walk every CallExpr / *ast.Ident / BinaryExpr that
	// evaluates to a static string starting with "userspace_".
	// This catches concat folds (AGY r2 §D) and const-ident
	// resolution (AGY r3 §ii).
	ast.Inspect(file, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			return true
		}
		folded, fok := evalStringExpr(bin, consts)
		if !fok {
			return true
		}
		if isMapNameSuspect(folded) {
			report(folded)
			markBasicLitOperands(bin, concatOperand)
		}
		return true
	})

	// Pass 2: walk every CallExpr argument — when the argument
	// resolves (via const-ident, concat, paren) to a static
	// "userspace_*" string, report it. Catches the AGY r3 §ii
	// const-ident bypass even when the const value is built from
	// other const idents. Also applies the trim-padded check
	// so AGY r3 §iii padded-const-ident bypasses are caught.
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if _, isLit := arg.(*ast.BasicLit); isLit {
				// Basic literals are covered by Pass 3.
				continue
			}
			s, ok := evalStringExpr(arg, consts)
			if !ok {
				continue
			}
			if isMapNameSuspect(s) {
				report(s)
				continue
			}
			// AGY r3 §iii: const value with non-ASCII whitespace
			// padding. Trim and re-check against the exact
			// registry.
			trimmed := trimPaddingForBypass(s)
			if trimmed != s && isExactRegistryMapName(trimmed) {
				report(trimmed)
			}
		}
		return true
	})

	// Pass 3: basic-literal walk for direct literals (including
	// trim-padded bypasses, AGY r2 §A and AGY r3 §iii).
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if concatOperand[lit] {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		// Standard rule: starts with "userspace_" and contains no
		// whitespace (unicode-aware so `\n`/`\r`/etc are caught).
		if strings.HasPrefix(s, "userspace_") && !containsUnicodeSpace(s) {
			report(s)
			return true
		}
		// Trim-padded rule: a literal padded with whitespace
		// (unicode-aware) or `%` verb characters whose trimmed
		// value exactly equals a registered map name is a bypass.
		trimmed := trimPaddingForBypass(s)
		if trimmed != s && isExactRegistryMapName(trimmed) {
			report(s)
		}
		return true
	})
	hits := make([]string, 0, len(hitSet))
	for s := range hitSet {
		hits = append(hits, s)
	}
	return hits, nil
}

// isMapNameSuspect returns true when s is a folded string that
// looks like a forbidden map-name alias. It is the entry point for
// the concat/ident passes; the basic-literal pass has additional
// trim-padded handling because only it sees raw literal padding.
func isMapNameSuspect(s string) bool {
	if !strings.HasPrefix(s, "userspace_") {
		return false
	}
	if containsUnicodeSpace(s) {
		// A folded value with whitespace is prose-like and
		// almost certainly not a map name. Real map names are
		// snake_case ASCII.
		return false
	}
	return true
}

// containsUnicodeSpace returns true if s contains any Unicode
// whitespace rune — including the non-ASCII characters AGY r3 §iii
// flagged as bypass material (e.g. \n, \r, NBSP).
func containsUnicodeSpace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// trimPaddingForBypass strips any leading/trailing whitespace
// (unicode-aware) and any `%` format-verb characters. Returns the
// trimmed value. AGY r3 §iii: must include all whitespace runes,
// not just space/tab.
func trimPaddingForBypass(s string) string {
	s = strings.TrimFunc(s, unicode.IsSpace)
	s = strings.Trim(s, "%")
	return s
}

// evalStringExpr folds an expression to a static string, walking
// BinaryExpr `+`, ParenExpr, BasicLit, and *ast.Ident (resolved
// against the supplied const symbol table). Returns the value and
// true on success. AGY r3 §ii: ident resolution closes the
// `const x = "a"; const y = "b"; const z = x + y` bypass.
func evalStringExpr(e ast.Expr, consts map[string]string) (string, bool) {
	switch n := e.(type) {
	case *ast.ParenExpr:
		return evalStringExpr(n.X, consts)
	case *ast.BasicLit:
		if n.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(n.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.Ident:
		if consts == nil {
			return "", false
		}
		v, ok := consts[n.Name]
		return v, ok
	case *ast.BinaryExpr:
		if n.Op != token.ADD {
			return "", false
		}
		l, lok := evalStringExpr(n.X, consts)
		if !lok {
			return "", false
		}
		r, rok := evalStringExpr(n.Y, consts)
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
			// Two hits expected: the raw padded literal (from
			// Pass 3 trim check) AND the trimmed clean value
			// (from Pass 2 call-arg trim check). Dedup keeps both
			// because they are distinct strings.
			want: []string{"userspace_ctrl ", "userspace_ctrl"},
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
		{
			name: "agy_r3_ii_const_ident_concat",
			src: `package x
const pfx = "user"
const sfx = "space_ctrl"
const bypass = pfx + sfx
func F(m M) { _ = m.Map(bypass) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r3 §ii: const-ident resolution. Two leaf
			// literals neither of which starts with "userspace_";
			// the folded value does. The const-symbol table closes
			// the bypass; reported on the const decl line.
			want: []string{"userspace_ctrl"},
		},
		{
			name: "agy_r3_ii_call_arg_via_ident",
			src: `package x
const bypass = "userspace_ctrl"
func F(m M) { _ = m.Map(bypass) }
type M struct{}
func (M) Map(string) any { return nil }
`,
			// AGY r3 §ii: call-arg ident resolution. The basic
			// literal in the const decl AND the call-arg via
			// ident both resolve to the same value; dedup is the
			// expected behaviour.
			want: []string{"userspace_ctrl"},
		},
		{
			name: "agy_r3_iii_newline_padding",
			src: "package x\nconst bypass = \"userspace_ctrl\\n\\t\"\nfunc F(m M) { _ = m.Map(bypass) }\ntype M struct{}\nfunc (M) Map(string) any { return nil }\n",
			// AGY r3 §iii: padding with non-space whitespace
			// (newline + tab). The trim-padded check must use
			// unicode.IsSpace; trimmed value equals
			// "userspace_ctrl" which matches the registry.
			// Reported on both the const decl literal and the
			// call-arg via ident resolution.
			want: []string{"userspace_ctrl\n\t", "userspace_ctrl"},
		},
		{
			name: "agy_r3_iii_nbsp_padding",
			src: "package x\nconst bypass = \"userspace_ctrl\\u00A0\"\nfunc F(m M) { _ = m.Map(bypass) }\ntype M struct{}\nfunc (M) Map(string) any { return nil }\n",
			// AGY r3 §iii: NBSP (U+00A0) is whitespace by Unicode.
			// trimPaddingForBypass uses unicode.IsSpace so NBSP is
			// stripped; trimmed value equals "userspace_ctrl".
			want: []string{"userspace_ctrl ", "userspace_ctrl"},
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

	// Dynamically discover every `mapName...` constant defined in
	// maps.go via AST parse. AGY r3 §v: a hardcoded list goes stale
	// when a new constant is added; using the AST keeps the parity
	// check self-extending.
	entries, err := parseMapsGoRegistry("maps.go")
	if err != nil {
		t.Fatalf("parse maps.go: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("parseMapsGoRegistry returned no constants — maps.go shape changed?")
	}
	for _, e := range entries {
		quoted := []byte(`"` + e.value + `"`)
		if !bytes.Contains(body, quoted) {
			t.Errorf(
				"%s = %q not found as a quoted literal in %s — "+
					"parity broken: rename both sides together or update this canary",
				e.name, e.value, loaderPath)
		}
	}
}

// registryEntry holds one constant from maps.go for parity checks.
type registryEntry struct {
	name  string
	value string
}

// parseMapsGoRegistry parses maps.go and returns every top-level
// `const mapName... = "..."` declaration. Skips comments, blank
// identifiers, and non-string values.
func parseMapsGoRegistry(path string) ([]registryEntry, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var out []registryEntry
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if !strings.HasPrefix(name.Name, "mapName") {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				out = append(out, registryEntry{name: name.Name, value: v})
			}
		}
	}
	return out, nil
}
