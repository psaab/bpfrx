package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #2114 (Codex PR #6743 r6-F1): the COMPLETENESS fence for optional-capability
// probes.
//
// The behavioural binders in daemon_dp_capability_2114_test.go prove the
// erasure is fixed for the sites they drive. They cannot prove it for the
// ~30 other probe sites across pkg/grpcapi, pkg/api and pkg/cli, and they
// cannot prove it for the NEXT one somebody adds — which is the failure
// mode that matters here, because the symptom of getting it wrong is
// silence (a metric family that stops being emitted, a paging path that
// quietly degrades) rather than an error.
//
// This canary states the syntactic half: in a consumer package, an
// optional-capability assertion must be made against dpProbe(), never
// against the stored `dp` field. `x.dp.(T)` reaches the daemon's live
// indirection, whose method set is exactly the mandatory surface, so the
// assertion answers "absent" for a healthy backend that has T.
//
// SCOPE — the EXACT spellings covered (Codex PR #6743 r7-F3). This is a
// fence against a handful of SPELLINGS of one mistake. It is not a
// completeness fence, and calling it one is what made the r6 comment
// misleading. Covered:
//
//  1. a type assertion on a `.dp` selector — `x.dp.(T)`, including any
//     number of parenthesization / dereference layers: `(x.dp).(T)`,
//     `((x.dp)).(T)`, `(*p).dp.(T)`;
//  2. a type SWITCH on the same — `switch x.dp.(type)`;
//  3. either of those on a local bound DIRECTLY from the field in the same
//     function — `d := s.dp; ...; d.(T)`, `var d = s.dp`, `d := &s.dp;
//     (*d).(T)`.
//
// Everything else passes clean, by construction:
//
//   - a helper that returns `s.dp` as `any`, and an assertion on ITS
//     result;
//   - a closure — `get := func() any { return s.dp }; get().(T)`;
//   - a FREE FUNCTION that takes the field as a parameter and asserts on
//     the parameter. This is not hypothetical: it is the exact shape of
//     pkg/api's fetchUserspaceStatus(dp apiRuntimeDataPlane), the site of
//     the original metric loss, whose correctness rests entirely on the
//     dataplane.Unwrap call in its body — the scanner cannot see across
//     that call boundary, and its live call site
//     `fetchUserspaceStatus(s.dp)` is CORRECT, so flagging `.dp` as a call
//     ARGUMENT would be a false positive, not coverage;
//   - a field with a different name (the scanner keys on the identifier
//     `dp`, not on the field's type — it has no type information).
//
// Those need dataflow, not syntax. Case 3 above is nonetheless worth the
// extra pass, because `rt := <handle>; rt.(T)` is the HOUSE IDIOM: an AST
// sweep found 19 instances of it in pkg/daemon, every one of them sound
// (they bind from the raw cell, where asserting on the alias is correct).
// A contributor copying that style into pkg/grpcapi writes `rt := s.dp;
// rt.(T)` — which is why the alias spelling is the likeliest of these to
// walk in, and why it is caught rather than merely disclaimed.
//
// The behavioural half — that the pattern actually preserves capabilities
// — is daemon_dp_capability_2114_test.go, plus pkg/cli's
// cli_capability_probe_2114_test.go. This canary only stops the spellings
// above from reappearing.

// probeConsumerDirs are the packages whose `dp` field the daemon fills
// with liveDataPlane (daemon_run_servers.go, daemon_run.go).
var probeConsumerDirs = []string{"../grpcapi", "../api", "../cli"}

// probeScanFiles returns the production .go files under root, RECURSIVELY.
//
// r7-F3c: both scanners in this file used os.ReadDir and skipped every
// subdirectory, so a consumer moved into a future pkg/api/<sub> would be
// unfenced without anything failing. testdata and dot-directories are
// excluded (fixtures and tooling, never production probes); _test.go stays
// exempt because tests wire concrete backends into dp directly, where the
// raw assertion is correct.
func probeScanFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != root && (name == "testdata" || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// unwrapProbeExpr strips parenthesization, pointer-dereference and
// address-of layers to reach the expression a probe is really made against.
//
// It deliberately mirrors the house helper unwrapOwnerIdent
// (pkg/dataplane/armed_gate_matrix_test.go), which this PR added for the
// same evasion class on the registry canary and which
// pkg/dataplane/README.md advertises as covering multi-layer parenthesized
// access: s.dp, (s.dp) and ((s.dp)) must all resolve to the same selector,
// or `(s.dp).(T)` walks straight past the fence (Codex PR #6743 r7-F3a).
// Anything that is not one of those layers is returned unchanged, so a call
// or an index expression cannot be mistaken for the field.
func unwrapProbeExpr(expr ast.Expr) ast.Expr {
	for {
		switch x := expr.(type) {
		case *ast.ParenExpr:
			expr = x.X
		case *ast.StarExpr:
			expr = x.X
		case *ast.UnaryExpr:
			if x.Op != token.AND {
				return expr
			}
			expr = x.X
		default:
			return expr
		}
	}
}

// dpFieldAliases returns the identifiers a function body binds DIRECTLY to
// a `.dp` selector (`d := s.dp`, `var d = s.dp`, and the parenthesized /
// address-of spellings of those). An assertion on such an alias reaches the
// same live indirection the field itself does, so r7-F3 treats it as the
// same violation. Assignments through a call, an interface conversion or a
// struct field are NOT aliases and are not tracked — see the scope note at
// the top of this file.
func dpFieldAliases(body *ast.BlockStmt) map[string]bool {
	aliases := map[string]bool{}
	record := func(lhs, rhs []ast.Expr) {
		if len(lhs) != len(rhs) {
			return
		}
		for i, r := range rhs {
			sel, ok := unwrapProbeExpr(r).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "dp" {
				continue
			}
			if id, ok := unwrapProbeExpr(lhs[i]).(*ast.Ident); ok && id.Name != "_" {
				aliases[id.Name] = true
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			record(s.Lhs, s.Rhs)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, 0, len(s.Names))
			for _, nm := range s.Names {
				lhs = append(lhs, nm)
			}
			record(lhs, s.Values)
		}
		return true
	})
	return aliases
}

// rawDPAssertionViolations reports the covered spellings (see the scope
// note at the top of this file) in the production sources under root,
// recursively. A type SWITCH head is an *ast.TypeAssertExpr with a nil
// Type, so both passes below accept it: `switch x.dp.(type)` erases
// capabilities exactly as `x.dp.(T)` does.
func rawDPAssertionViolations(t *testing.T, root string) []string {
	t.Helper()

	files, err := probeScanFiles(root)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	var violations []string
	seen := map[string]bool{}
	for _, path := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = filepath.Base(path)
		}
		add := func(pos token.Position, why string) {
			v := filepath.Base(root) + "/" + rel + ":" + probeLineNo(pos.Line) + " (" + why + ")"
			if seen[v] {
				return
			}
			seen[v] = true
			violations = append(violations, v)
		}

		// Pass A (file-wide): assertions and type switches directly on the
		// `.dp` selector, through any number of parenthesization layers.
		ast.Inspect(file, func(n ast.Node) bool {
			assert, ok := n.(*ast.TypeAssertExpr)
			if !ok {
				return true
			}
			sel, ok := unwrapProbeExpr(assert.X).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "dp" {
				return true
			}
			add(fset.Position(assert.Pos()), dpAssertionKind(assert)+" on the dp field")
			return true
		})

		// Pass B (per function): the same two shapes on a local alias of
		// the field.
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			aliases := dpFieldAliases(fn.Body)
			if len(aliases) == 0 {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assert, ok := n.(*ast.TypeAssertExpr)
				if !ok {
					return true
				}
				id, ok := unwrapProbeExpr(assert.X).(*ast.Ident)
				if !ok || !aliases[id.Name] {
					return true
				}
				add(fset.Position(assert.Pos()),
					dpAssertionKind(assert)+" on "+id.Name+", a local alias of the dp field")
				return true
			})
		}
	}
	sort.Strings(violations)
	return violations
}

// dpAssertionKind names the spelling, so the failure message says which of
// the covered forms was found.
func dpAssertionKind(assert *ast.TypeAssertExpr) string {
	if assert.Type == nil {
		return "type switch"
	}
	return "type assertion"
}

func probeLineNo(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestOptionalCapabilityProbesUseDPProbe fences the three covered
// spellings across the whole consumer set.
//
// Fail-on-revert: change any probe back to `s.dp.(userspaceStatusProvider)`
// / `c.dp.(cliSessionCursor)` / `s.dp.(sessionCursorIterator)`, or to
// `switch s.dp.(type)`, or via a local `d := s.dp`, and that site is
// reported here — including the sites in pkg/cli, which only run under
// isInteractive() and have no unit-reachable path at all. It does NOT
// claim to catch every way a probe can erase a capability; see the scope
// note at the top of this file and
// TestOptionalCapabilityProbeScannerDocumentedGaps.
func TestOptionalCapabilityProbesUseDPProbe(t *testing.T) {
	t.Parallel()

	var all []string
	for _, dir := range probeConsumerDirs {
		all = append(all, rawDPAssertionViolations(t, dir)...)
	}
	if len(all) > 0 {
		t.Fatalf("optional-capability assertions made against the stored dp field instead of "+
			"dpProbe(): under the #2114 live indirection these answer \"capability absent\" for a "+
			"HEALTHY backend that implements it.\n%s", strings.Join(all, "\n"))
	}
}

// TestOptionalCapabilityProbesUseDPProbeSelfTest drives the scanner in
// BOTH directions, so a scanner that silently stopped matching cannot make
// the fence above vacuously green.
func TestOptionalCapabilityProbesUseDPProbeSelfTest(t *testing.T) {
	t.Parallel()

	good := `package consumer

type Server struct{ dp any }

type statusProvider interface{ Status() int }

func Unwrap(v any) any { return v }

func (s *Server) dpProbe() any { return Unwrap(s.dp) }

func (s *Server) status() int {
	p, ok := s.dpProbe().(statusProvider)
	if !ok {
		return 0
	}
	return p.Status()
}
`
	bad := `package consumer

type Server2 struct{ dp any }

type cursorProvider interface{ Cursor() int }

func (s *Server2) cursor() int {
	p, ok := s.dp.(cursorProvider)
	if !ok {
		return 0
	}
	return p.Cursor()
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.go"), []byte(good), 0o644); err != nil {
		t.Fatalf("write good fixture: %v", err)
	}
	if v := rawDPAssertionViolations(t, dir); len(v) > 0 {
		t.Fatalf("dpProbe-routed fixture reported violations: %v", v)
	}

	if err := os.WriteFile(filepath.Join(dir, "bad.go"), []byte(bad), 0o644); err != nil {
		t.Fatalf("write bad fixture: %v", err)
	}
	v := rawDPAssertionViolations(t, dir)
	if len(v) != 1 || !strings.Contains(v[0], "bad.go") {
		t.Fatalf("raw-field fixture violations = %v, want exactly one naming bad.go", v)
	}

	// A _test.go file carrying the raw shape is NOT a violation: tests wire
	// concrete backends into dp directly, where the assertion is correct.
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(strings.Replace(bad, "Server2", "Server3", -1)), 0o644); err != nil {
		t.Fatalf("write test-file fixture: %v", err)
	}
	if v := rawDPAssertionViolations(t, dir); len(v) != 1 {
		t.Fatalf("_test.go must be exempt; violations = %v", v)
	}

	// r7-F3c: a violation in a SUBDIRECTORY must be reported. The r6
	// scanner skipped every directory entry, so this shape was invisible.
	sub := filepath.Join(dir, "inner")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "deep.go"),
		[]byte(strings.Replace(bad, "Server2", "ServerDeep", -1)), 0o644); err != nil {
		t.Fatalf("write subdir fixture: %v", err)
	}
	if v := rawDPAssertionViolations(t, dir); len(v) != 2 {
		t.Fatalf("a violation in a SUBDIRECTORY must be reported; violations = %v", v)
	}

	// ... but testdata is excluded: it holds fixtures, never production probes.
	td := filepath.Join(dir, "testdata")
	if err := os.Mkdir(td, 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(td, "fixture.go"),
		[]byte(strings.Replace(bad, "Server2", "ServerTD", -1)), 0o644); err != nil {
		t.Fatalf("write testdata fixture: %v", err)
	}
	if v := rawDPAssertionViolations(t, dir); len(v) != 2 {
		t.Fatalf("testdata must be excluded; violations = %v", v)
	}

	// r7-F3: the two spellings the r6 scanner let through. Each gets its
	// own directory so the count is unambiguous.
	typeSwitch := `package consumer

type Server4 struct{ dp any }

type cursorProvider4 interface{ Cursor() int }

func (s *Server4) cursor() int {
	switch p := s.dp.(type) {
	case cursorProvider4:
		return p.Cursor()
	default:
		return 0
	}
}
`
	alias := `package consumer

type Server5 struct{ dp any }

type cursorProvider5 interface{ Cursor() int }

func (s *Server5) cursor() int {
	d := s.dp
	p, ok := d.(cursorProvider5)
	if !ok {
		return 0
	}
	return p.Cursor()
}
`
	// r7-F3a: the parenthesization / dereference layers. `(s.dp).(T)` walked
	// straight past the r6 scanner because assert.X was an *ast.ParenExpr.
	// The house helper unwrapOwnerIdent already covered this class for the
	// registry canary, so the fence has to match it — one layer is not
	// enough, which is why ((...)) is here too.
	parens := `package consumer

type Server6 struct{ dp any }

type cursorProvider6 interface{ Cursor() int }

func (s *Server6) cursor() int {
	p, ok := (s.dp).(cursorProvider6)
	if !ok {
		return 0
	}
	return p.Cursor()
}
`
	doubleParens := `package consumer

type Server7 struct{ dp any }

type cursorProvider7 interface{ Cursor() int }

func (s *Server7) cursor() int {
	p, ok := ((s.dp)).(cursorProvider7)
	if !ok {
		return 0
	}
	return p.Cursor()
}
`
	starField := `package consumer

type Server8 struct{ dp any }

type cursorProvider8 interface{ Cursor() int }

func cursor8(p *Server8) int {
	c, ok := (*p).dp.(cursorProvider8)
	if !ok {
		return 0
	}
	return c.Cursor()
}
`
	addrOfAlias := `package consumer

type Server9 struct{ dp any }

type cursorProvider9 interface{ Cursor() int }

func (s *Server9) cursor() int {
	d := &s.dp
	p, ok := (*d).(cursorProvider9)
	if !ok {
		return 0
	}
	return p.Cursor()
}
`
	for _, tc := range []struct {
		name string
		src  string
		want string
	}{
		{"type switch on the field", typeSwitch, "type switch"},
		{"assertion on a local alias", alias, "local alias"},
		{"parenthesized field", parens, "on the dp field"},
		{"doubly parenthesized field", doubleParens, "on the dp field"},
		{"field through a dereferenced receiver", starField, "on the dp field"},
		{"dereferenced address-of alias", addrOfAlias, "local alias"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			if err := os.WriteFile(filepath.Join(d, "x.go"), []byte(tc.src), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			v := rawDPAssertionViolations(t, d)
			if len(v) != 1 || !strings.Contains(v[0], tc.want) {
				t.Fatalf("violations = %v, want exactly one containing %q", v, tc.want)
			}
		})
	}
}

// TestOptionalCapabilityProbeScannerDocumentedGaps pins the BOUNDARY the
// scope note at the top of this file claims (Codex PR #6743 r7-F3).
//
// It asserts that the three inter-procedural / renamed shapes are NOT
// reported. That is not an endorsement of them — it is the executable half
// of the documentation: if someone widens the scanner to cover one of
// these, this test fails and forces the scope note to be updated, and if
// the scope note is WRONG today (a shape it disclaims is in fact caught)
// this test fails now. Silence about coverage is what made the r6 comment
// misleading in the first place.
func TestOptionalCapabilityProbeScannerDocumentedGaps(t *testing.T) {
	t.Parallel()

	// The exact shape of pkg/api's fetchUserspaceStatus: the field is
	// passed to a free function that asserts on its PARAMETER. The call
	// site `s.dp` is correct in production, so it must not be flagged
	// either.
	freeFunc := `package consumer

type statusProvider interface{ Status() int }

func fetch(dp any) int {
	p, ok := dp.(statusProvider)
	if !ok {
		return 0
	}
	return p.Status()
}

type Gap1 struct{ dp any }

func (s *Gap1) status() int { return fetch(s.dp) }
`
	// A helper that RETURNS the field as any, with the assertion on the
	// helper's result.
	helper := `package consumer

type Gap2 struct{ dp any }

type statusProviderG2 interface{ Status() int }

func (s *Gap2) raw() any { return s.dp }

func (s *Gap2) status() int {
	p, ok := s.raw().(statusProviderG2)
	if !ok {
		return 0
	}
	return p.Status()
}
`
	// A differently-named field: the scanner keys on the identifier, not
	// on the type (it has no type information).
	renamed := `package consumer

type Gap3 struct{ backend any }

type statusProviderG3 interface{ Status() int }

func (s *Gap3) status() int {
	p, ok := s.backend.(statusProviderG3)
	if !ok {
		return 0
	}
	return p.Status()
}
`
	// A closure that returns the field; the assertion is on the CALL.
	closure := `package consumer

type Gap4 struct{ dp any }

type statusProviderG4 interface{ Status() int }

func (s *Gap4) status() int {
	get := func() any { return s.dp }
	p, ok := get().(statusProviderG4)
	if !ok {
		return 0
	}
	return p.Status()
}
`
	for _, tc := range []struct{ name, src string }{
		{"free function taking the field as a parameter", freeFunc},
		{"helper returning the field as any", helper},
		{"differently named field", renamed},
		{"closure returning the field", closure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			if err := os.WriteFile(filepath.Join(d, "x.go"), []byte(tc.src), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			if v := rawDPAssertionViolations(t, d); len(v) != 0 {
				t.Fatalf("the scope note says this shape is NOT covered, but the scanner "+
					"reported %v — widen the note (or narrow the scanner)", v)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// #6743 r6-F2: one resolution per operation.
// ---------------------------------------------------------------------------

// persistentNATConsumerDirs are the packages that call GetPersistentNAT on
// a handle the daemon may fill with the live indirection.
var persistentNATConsumerDirs = []string{"../grpcapi", "../api", "../cli", "../natshow"}

// repeatedPersistentNATResolutions reports every production function that
// calls GetPersistentNAT more than once.
//
// Under the live indirection each call is a SEPARATE cell load, so a
// second call can return nil to a caller that already proved the first
// non-nil — a nil dereference in a `clear` / `show` handler. The rule is
// therefore syntactic and absolute: resolve once, bind to a local.
func repeatedPersistentNATResolutions(t *testing.T, root string) []string {
	t.Helper()

	files, err := probeScanFiles(root)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	var violations []string
	for _, path := range files {
		name, relErr := filepath.Rel(root, path)
		if relErr != nil {
			name = filepath.Base(path)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			calls := 0
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "GetPersistentNAT" {
					calls++
				}
				return true
			})
			if calls > 1 {
				violations = append(violations,
					filepath.Base(root)+"/"+name+":"+fn.Name.Name+
						" resolves GetPersistentNAT "+probeLineNo(calls)+" times")
			}
		}
	}
	sort.Strings(violations)
	return violations
}

// TestPersistentNATResolvedOncePerOperation fences every consumer PACKAGE
// (recursively since r7-F3c), including pkg/cli's clearPersistentNAT —
// which runs only under isInteractive() and has no unit-reachable path, so
// the behavioural binders (pkg/daemon's SystemAction test, pkg/natshow's
// render tests) cannot reach it.
//
// Codex PR #6743 r7: the rule it enforces is per-FUNCTION — more than one
// GetPersistentNAT call inside one function body. A check-then-use split
// ACROSS two functions still resolves twice and is not reported; that needs
// dataflow, not syntax, and is the same documented boundary as the
// optional-probe scanner above.
func TestPersistentNATResolvedOncePerOperation(t *testing.T) {
	t.Parallel()

	var all []string
	for _, dir := range persistentNATConsumerDirs {
		all = append(all, repeatedPersistentNATResolutions(t, dir)...)
	}
	if len(all) > 0 {
		t.Fatalf("GetPersistentNAT resolved more than once in one operation: under the #2114 live "+
			"indirection each call is a fresh cell load, so a check-then-use pair nil-dereferences "+
			"when the daemon disowns the backend in between.\n%s", strings.Join(all, "\n"))
	}
}

// TestPersistentNATResolvedOncePerOperationSelfTest drives the scanner in
// both directions so the fence above cannot be vacuously green.
func TestPersistentNATResolvedOncePerOperationSelfTest(t *testing.T) {
	t.Parallel()

	good := `package consumer

type table struct{}

func (t *table) Len() int { return 0 }

type srv struct{}

func (s *srv) GetPersistentNAT() *table { return nil }

func (s *srv) clear() int {
	tbl := s.GetPersistentNAT()
	if tbl == nil {
		return 0
	}
	return tbl.Len()
}
`
	bad := `package consumer

type srv2 struct{}

func (s *srv2) GetPersistentNAT() *table { return nil }

func (s *srv2) clear2() int {
	if s.GetPersistentNAT() == nil {
		return 0
	}
	return s.GetPersistentNAT().Len()
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.go"), []byte(good), 0o644); err != nil {
		t.Fatalf("write good fixture: %v", err)
	}
	if v := repeatedPersistentNATResolutions(t, dir); len(v) > 0 {
		t.Fatalf("single-resolution fixture reported violations: %v", v)
	}

	if err := os.WriteFile(filepath.Join(dir, "bad.go"), []byte(bad), 0o644); err != nil {
		t.Fatalf("write bad fixture: %v", err)
	}
	v := repeatedPersistentNATResolutions(t, dir)
	if len(v) != 1 || !strings.Contains(v[0], "clear2") {
		t.Fatalf("check-then-use fixture violations = %v, want exactly one naming clear2", v)
	}
}
