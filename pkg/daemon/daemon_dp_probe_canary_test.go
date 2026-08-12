package daemon

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
// It is deliberately NOT a reachability claim. It is the "no new
// capability-erasing probe" fence around the behaviourally proven pattern.

// probeConsumerDirs are the packages whose `dp` field the daemon fills
// with liveDataPlane (daemon_run_servers.go, daemon_run.go).
var probeConsumerDirs = []string{"../grpcapi", "../api", "../cli"}

// rawDPAssertionViolations reports every `<expr>.dp.(T)` type assertion in
// the production sources under root.
func rawDPAssertionViolations(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s/%s: %v", root, name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			assert, ok := n.(*ast.TypeAssertExpr)
			if !ok || assert.Type == nil { // Type == nil is a type switch
				return true
			}
			sel, ok := assert.X.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "dp" {
				return true
			}
			pos := fset.Position(assert.Pos())
			violations = append(violations,
				filepath.Base(root)+"/"+name+":"+probeLineNo(pos.Line))
			return true
		})
	}
	sort.Strings(violations)
	return violations
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

// TestOptionalCapabilityProbesUseDPProbe is the whole-consumer-set fence.
//
// Fail-on-revert: change any probe back to `s.dp.(userspaceStatusProvider)`
// / `c.dp.(cliSessionCursor)` / `s.dp.(sessionCursorIterator)` and that
// site is reported here — including the sites in pkg/cli, which only run
// under isInteractive() and have no unit-reachable path at all.
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

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s/%s: %v", root, name, err)
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

// TestPersistentNATResolvedOncePerOperation fences every consumer,
// including pkg/cli's clearPersistentNAT — which runs only under
// isInteractive() and has no unit-reachable path, so the behavioural
// binders (pkg/daemon's SystemAction test, pkg/natshow's render tests)
// cannot reach it.
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
