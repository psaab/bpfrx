package dataplane

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

const (
	repoRootForBoundaryCanary       = "../.."
	rootDataplaneImportForCanary    = "github.com/psaab/xpf/pkg/dataplane"
	ciliumEBPFImportForCanary       = "github.com/cilium/ebpf"
	dpdkBackendImportForCanary      = "github.com/psaab/xpf/pkg/dataplane/dpdk"
	retirementBoundaryDocsForCanary = "../../docs/pr/1373-retire-ebpf-dataplane/README.md"
)

var legacyDataplaneImportAllowlist = map[string]string{
	"cmd/xpfd/main.go":                         "backend selection, cleanup, and backend registration",
	"pkg/api/handlers.go":                      "REST handlers still receive the legacy dataplane bridge",
	"pkg/api/handlers_sessions.go":             "REST session reads still use legacy session types",
	"pkg/api/metrics.go":                       "Prometheus telemetry still reads legacy counters and metadata",
	"pkg/api/server.go":                        "REST server constructor still stores the legacy bridge",
	"pkg/cli/cli.go":                           "embedded CLI constructor still stores the legacy bridge",
	"pkg/cli/cli_clear.go":                     "clear commands still delete legacy session entries",
	"pkg/cli/cli_show_flow.go":                 "flow display still uses legacy session keys and values",
	"pkg/cli/cli_show_nat.go":                  "NAT display still uses legacy NAT/session metadata",
	"pkg/cli/cli_show_security.go":             "security display still uses legacy counters and filter types",
	"pkg/cluster/sync.go":                      "session sync still installs sessions through the legacy bridge",
	"pkg/cluster/sync_bulk.go":                 "bulk sync still serializes legacy session entries",
	"pkg/cluster/sync_conn.go":                 "sync connection code still references legacy session types",
	"pkg/cluster/sync_protocol.go":             "wire protocol still carries legacy session records",
	"pkg/conntrack/gc.go":                      "GC compatibility constructor still adapts legacy sessions",
	"pkg/daemon/daemon.go":                     "daemon owns RuntimeDataPlane and exposes legacyDP for unmigrated callers",
	"pkg/daemon/daemon_apply.go":               "apply path still adapts legacy compile/apply metadata",
	"pkg/daemon/daemon_flow.go":                "flow logging still formats legacy dataplane counters",
	"pkg/daemon/daemon_ha.go":                  "HA state updates still call legacy bridge methods",
	"pkg/daemon/daemon_ha_fabric.go":           "fabric HA updates still call legacy bridge methods",
	"pkg/daemon/daemon_ha_userspace.go":        "userspace HA control still crosses the legacy bridge",
	"pkg/daemon/daemon_run.go":                 "runtime wiring still passes legacyDP to unmigrated services",
	"pkg/grpcapi/apply_result.go":              "gRPC apply metadata still adapts legacy apply results",
	"pkg/grpcapi/server.go":                    "gRPC server constructor still stores the legacy bridge",
	"pkg/grpcapi/server_helpers.go":            "gRPC helpers still format legacy dataplane types",
	"pkg/grpcapi/server_nat.go":                "gRPC NAT output still reads legacy NAT/session metadata",
	"pkg/grpcapi/server_sessions.go":           "gRPC session RPCs still use legacy session types",
	"pkg/grpcapi/server_show.go":               "gRPC show dispatcher still reaches legacy dataplane state",
	"pkg/grpcapi/server_show_cluster_text.go":  "cluster text output still reads legacy dataplane state",
	"pkg/grpcapi/server_show_flow.go":          "flow text output still uses legacy session keys and values",
	"pkg/grpcapi/server_show_nat.go":           "NAT text output still uses legacy NAT/session metadata",
	"pkg/grpcapi/server_show_policies_text.go": "policy text output still uses legacy counters",
	"pkg/grpcapi/server_show_security_text.go": "security text output still uses legacy counters and filter types",
	"pkg/grpcapi/server_show_status.go":        "status output still reads legacy dataplane state",
	"pkg/grpcapi/server_show_zones.go":         "zone output still uses legacy dataplane types",
	"pkg/logging/ringbuf.go":                   "event reader still consumes the legacy EventSource",
	"pkg/monitoriface/monitor.go":              "interface monitor still reads legacy interface counters",
}

var dpdkEBPFImportAllowlist = map[string]string{
	"pkg/dataplane/dpdk/manager.go": "legacy DataPlane Map method returns *ebpf.Map until DPDK migrates off root DataPlane",
}

var dpdkBackendImportAllowlist = map[string]string{
	"cmd/xpfd/main.go": "backend registration and cleanup entry point",
}

func TestOperatorPackagesOnlyUseDocumentedLegacyDataplaneImports(t *testing.T) {
	t.Parallel()

	found := map[string]bool{}
	var unexpected []string
	for _, path := range productionGoFilesUnder(t, operatorRuntimeBoundaryRoots(t)) {
		for _, imp := range importPaths(t, path) {
			if imp != rootDataplaneImportForCanary {
				continue
			}
			rel := repoRelativePath(t, path)
			found[rel] = true
			if _, ok := legacyDataplaneImportAllowlist[rel]; !ok {
				unexpected = append(unexpected, rel)
			}
		}
	}

	var stale []string
	for rel := range legacyDataplaneImportAllowlist {
		if !found[rel] {
			stale = append(stale, rel)
		}
	}

	if len(unexpected) > 0 || len(stale) > 0 {
		sort.Strings(unexpected)
		sort.Strings(stale)
		t.Fatalf(
			"legacy pkg/dataplane import allowlist drift\nunexpected imports: %v\nstale allowlist entries: %v\nupdate legacyDataplaneImportAllowlist and the #1451 docs table with any intentional change",
			unexpected,
			stale,
		)
	}
}

func TestOperatorPackagesDoNotImportBPFArtifactsDirectly(t *testing.T) {
	t.Parallel()

	var violations []string
	for _, path := range productionGoFilesUnder(t, operatorRuntimeBoundaryRoots(t)) {
		rel := repoRelativePath(t, path)
		for _, imp := range importPaths(t, path) {
			if imp == ciliumEBPFImportForCanary || strings.HasPrefix(imp, ciliumEBPFImportForCanary+"/") {
				violations = append(violations, rel+" imports "+imp)
			}
			if imp == dpdkBackendImportForCanary || strings.HasPrefix(imp, dpdkBackendImportForCanary+"/") {
				if rel != "cmd/xpfd/main.go" {
					violations = append(violations, rel+" imports "+imp)
				}
			}
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("operator packages must stay behind RuntimeDataPlane/BPF artifact boundaries: %v", violations)
	}
}

func TestDPDKBackendImportStaysBackendLocal(t *testing.T) {
	t.Parallel()

	var violations []string
	for _, path := range productionGoFilesUnder(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "cmd"),
		filepath.Join(repoRootForBoundaryCanary, "pkg"),
	}) {
		rel := repoRelativePath(t, path)
		if strings.HasPrefix(rel, "pkg/dataplane/dpdk/") {
			continue
		}
		if _, ok := dpdkBackendImportAllowlist[rel]; ok {
			continue
		}
		for _, imp := range importPaths(t, path) {
			if imp == dpdkBackendImportForCanary || strings.HasPrefix(imp, dpdkBackendImportForCanary+"/") {
				violations = append(violations, rel+" imports "+imp)
			}
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("DPDK backend imports must stay limited to pkg/dataplane/dpdk and cmd/xpfd registration: %v", violations)
	}
}

func TestDPDKEBPFArtifactImportsStayAtLegacyAdapter(t *testing.T) {
	t.Parallel()

	found := map[string]bool{}
	var unexpected []string
	for _, path := range productionGoFilesUnder(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "dpdk"),
	}) {
		rel := repoRelativePath(t, path)
		for _, imp := range importPaths(t, path) {
			if imp != ciliumEBPFImportForCanary && !strings.HasPrefix(imp, ciliumEBPFImportForCanary+"/") {
				continue
			}
			found[rel] = true
			if _, ok := dpdkEBPFImportAllowlist[rel]; !ok {
				unexpected = append(unexpected, rel+" imports "+imp)
			}
		}
	}

	var stale []string
	for rel := range dpdkEBPFImportAllowlist {
		if !found[rel] {
			stale = append(stale, rel)
		}
	}

	if len(unexpected) > 0 || len(stale) > 0 {
		sort.Strings(unexpected)
		sort.Strings(stale)
		t.Fatalf(
			"DPDK eBPF artifact import policy drift\nunexpected imports: %v\nstale allowlist entries: %v",
			unexpected,
			stale,
		)
	}
}

func TestDaemonRuntimeEntryPointUsesRuntimeDataPlane(t *testing.T) {
	t.Parallel()

	assertDaemonDPFieldIsRuntimeDataPlane(t)

	daemonRun := filepath.Join("..", "daemon", "daemon_run.go")
	if hasDaemonRuntimeConstructorCall(t, daemonRun, "NewDataPlane") {
		t.Fatal("daemon runtime startup must call NewRuntimeDataPlane, not NewDataPlane")
	}
	if !hasDaemonRuntimeConstructorCall(t, daemonRun, "NewRuntimeDataPlane") {
		t.Fatal("daemon runtime startup no longer calls dataplane.NewRuntimeDataPlane")
	}
}

func TestRetirementBoundaryDocsMentionDPDKPolicy(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(retirementBoundaryDocsForCanary)
	if err != nil {
		t.Fatalf("read retirement boundary docs: %v", err)
	}
	text := string(data)

	want := []string{
		"## #1475 DPDK Backend Policy",
		"DPDK remains a separately supported backend",
		"outside the eBPF source-removal path",
		"`pkg/dataplane/dpdk`",
		"`cmd/xpfd/main.go`",
		"`-tags dpdk`",
		"root `DataPlane`",
	}
	var missing []string
	for _, token := range want {
		if !strings.Contains(text, token) {
			missing = append(missing, token)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("retirement docs do not mention DPDK policy tokens: %v", missing)
	}
}

func TestRetirementBoundaryDocsMentionLegacyImportAllowlist(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(retirementBoundaryDocsForCanary)
	if err != nil {
		t.Fatalf("read retirement boundary docs: %v", err)
	}
	text := string(data)

	var missing []string
	for rel := range legacyDataplaneImportAllowlist {
		if !strings.Contains(text, rel) {
			missing = append(missing, rel)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("retirement docs do not mention allowlisted legacy imports: %v", missing)
	}
}

func operatorRuntimeBoundaryRoots(t *testing.T) []string {
	t.Helper()

	var roots []string
	for _, pattern := range []string{
		filepath.Join(repoRootForBoundaryCanary, "cmd", "*"),
		filepath.Join(repoRootForBoundaryCanary, "pkg", "*"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat %s: %v", path, err)
			}
			if !info.IsDir() {
				continue
			}
			if repoRelativePath(t, path) == "pkg/dataplane" {
				continue
			}
			roots = append(roots, path)
		}
	}
	sort.Strings(roots)
	return roots
}

func productionGoFilesUnder(t *testing.T, roots []string) []string {
	t.Helper()

	var files []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	sort.Strings(files)
	return files
}

func importPaths(t *testing.T, path string) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse imports for %s: %v", path, err)
	}

	imports := make([]string, 0, len(file.Imports))
	for _, imp := range file.Imports {
		imports = append(imports, strings.Trim(imp.Path.Value, `"`))
	}
	return imports
}

func repoRelativePath(t *testing.T, path string) string {
	t.Helper()

	root, err := filepath.Abs(repoRootForBoundaryCanary)
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs path for %s: %v", path, err)
	}
	rel, err := filepath.Rel(root, absPath)
	if err != nil {
		t.Fatalf("rel path for %s: %v", path, err)
	}
	return filepath.ToSlash(rel)
}

func hasDaemonRuntimeConstructorCall(t *testing.T, path, name string) bool {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	want := "dataplane." + name
	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if canaryExprString(call.Fun) == want {
			found = true
			return false
		}
		return true
	})
	return found
}

func assertDaemonDPFieldIsRuntimeDataPlane(t *testing.T) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "daemon", "daemon.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}

	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "Daemon" {
			return true
		}
		st, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			t.Fatalf("Daemon is %T, want struct", typeSpec.Type)
		}
		for _, field := range st.Fields.List {
			for _, name := range field.Names {
				if name.Name != "dp" {
					continue
				}
				found = true
				if got := canaryExprString(field.Type); got != "dataplane.RuntimeDataPlane" {
					t.Fatalf("Daemon.dp = %s, want dataplane.RuntimeDataPlane", got)
				}
			}
		}
		return false
	})

	if !found {
		t.Fatal("Daemon.dp field not found")
	}
}

func canaryExprString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return canaryExprString(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + canaryExprString(e.X)
	default:
		return ""
	}
}
