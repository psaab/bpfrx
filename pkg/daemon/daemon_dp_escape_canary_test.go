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

// #2114 (Codex PR #6743 r4-F4): the COMPLETENESS canary for the
// management-surface conversion.
//
// The behavioural binders (daemon_dp_escape_test.go for gRPC,
// daemon_dp_escape_rest_test.go for REST) prove the live indirection
// actually works end to end. They cannot prove that the THIRD converted
// site — the console CLI, which only runs under isInteractive() and so
// has no unit-reachable startup path — still uses it, nor that a FOURTH
// management consumer added later will.
//
// This canary states the syntactic half: a production function that
// declares a management-probe variable must source it from
// liveDataplane(). It is deliberately NOT a reachability claim; it is
// the "no new capture-once consumer" fence around the behaviourally
// proven pattern.

// managementProbeTypes are the daemon-local probe types whose values are
// handed to a LONG-LIVED downstream consumer (grpcapi.Server.dp,
// api.Server.dp, cli.CLI.dp). dataplaneReadyProbe / natSeeder /
// fibSyncStarter are deliberately absent: those are used inline within a
// single statement and never stored.
var managementProbeTypes = map[string]bool{
	"apiDataPlane":  true,
	"grpcDataPlane": true,
	"cliDataPlane":  true,
}

// managementProbeDeclFiles are the files allowed to name a management
// probe type WITHOUT calling liveDataplane: the declaration site and the
// live adapter's own compile-time assertions.
var managementProbeDeclFiles = map[string]bool{
	"runtime_probes.go": true,
	"daemon_dp_live.go": true,
}

// captureOnceProbeViolations reports every production function that
// declares a management-probe variable but never calls liveDataplane.
func captureOnceProbeViolations(t *testing.T, root string) []string {
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
		if managementProbeDeclFiles[name] {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			probes := declaredProbeTypesIn(fn.Body)
			if len(probes) == 0 {
				continue
			}
			if callsLiveDataplaneIn(fn.Body) {
				continue
			}
			violations = append(violations, name+":"+fn.Name.Name+" declares "+
				strings.Join(probes, ",")+" without liveDataplane()")
		}
	}
	sort.Strings(violations)
	return violations
}

// declaredProbeTypesIn returns the management-probe type names that body
// declares a variable of (`var x grpcDataPlane`), deduplicated.
func declaredProbeTypesIn(body *ast.BlockStmt) []string {
	seen := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		ident, ok := spec.Type.(*ast.Ident)
		if !ok || !managementProbeTypes[ident.Name] {
			return true
		}
		seen[ident.Name] = true
		return true
	})
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// callsLiveDataplaneIn reports whether body calls x.liveDataplane().
func callsLiveDataplaneIn(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "liveDataplane" {
			return true
		}
		found = true
		return false
	})
	return found
}

// TestManagementProbesComeFromLiveDataplane is the whole-package fence.
// It covers the CLI site in daemon_run.go, which the behavioural binders
// cannot reach.
//
// Fail-on-revert: restore the capture-once wiring at ANY of the three
// call sites (startGRPCServer, startHTTPServer, or the isInteractive()
// block in Run) and that function names a probe type with no
// liveDataplane() call, so it is reported here.
func TestManagementProbesComeFromLiveDataplane(t *testing.T) {
	t.Parallel()

	if v := captureOnceProbeViolations(t, "."); len(v) > 0 {
		t.Fatalf("management-probe values taken as a capture-once snapshot instead of the "+
			"#2114 live indirection:\n%s", strings.Join(v, "\n"))
	}
}

// TestManagementProbesComeFromLiveDataplaneSelfTest drives the scanner in
// BOTH directions over synthetic fixtures, so a scanner that silently
// stopped matching cannot make the fence above vacuously green.
func TestManagementProbesComeFromLiveDataplaneSelfTest(t *testing.T) {
	t.Parallel()

	live := `package daemon

type grpcDataPlane interface{ IsLoaded() bool }

type Daemon struct{}

func (d *Daemon) liveDataplane() (grpcDataPlane, bool) { return nil, false }

func (d *Daemon) startGRPCServer() {
	var grpcDP grpcDataPlane
	if l, ok := d.liveDataplane(); ok {
		grpcDP = l
	}
	_ = grpcDP
}
`
	captured := `package daemon

type cliDataPlane interface{ IsLoaded() bool }

type Daemon2 struct{}

func (d *Daemon2) dataplane() any { return nil }

func (d *Daemon2) startShell() {
	var cliDP cliDataPlane
	if rt := d.dataplane(); rt != nil {
		if probe, ok := rt.(cliDataPlane); ok {
			cliDP = probe
		}
	}
	_ = cliDP
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "live.go"), []byte(live), 0o644); err != nil {
		t.Fatalf("write live fixture: %v", err)
	}
	if v := captureOnceProbeViolations(t, dir); len(v) > 0 {
		t.Fatalf("live-wired fixture reported violations: %v", v)
	}

	if err := os.WriteFile(filepath.Join(dir, "captured.go"), []byte(captured), 0o644); err != nil {
		t.Fatalf("write captured fixture: %v", err)
	}
	v := captureOnceProbeViolations(t, dir)
	if len(v) != 1 || !strings.Contains(v[0], "startShell") || !strings.Contains(v[0], "cliDataPlane") {
		t.Fatalf("captured fixture violations = %v, want exactly one naming startShell/cliDataPlane", v)
	}

	// The allowlist must be file-scoped, not global: a probe declaration
	// inside runtime_probes.go is exempt, the same shape elsewhere is not.
	exempt := t.TempDir()
	if err := os.WriteFile(filepath.Join(exempt, "runtime_probes.go"), []byte(captured), 0o644); err != nil {
		t.Fatalf("write exempt fixture: %v", err)
	}
	if v := captureOnceProbeViolations(t, exempt); len(v) > 0 {
		t.Fatalf("runtime_probes.go should be exempt, got %v", v)
	}
}
