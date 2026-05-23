package dataplane

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

const (
	repoRootForBoundaryCanary       = "../.."
	rootDataplaneImportForCanary    = "github.com/psaab/xpf/pkg/dataplane"
	ciliumEBPFImportForCanary       = "github.com/cilium/ebpf"
	dpdkBackendImportForCanary      = "github.com/psaab/xpf/pkg/dataplane/dpdk"
	makefileForCanary               = "../../Makefile"
	retirementBoundaryDocsForCanary = "../../docs/pr/1373-retire-ebpf-dataplane/README.md"
	userspaceXDPEntryProgForCanary  = "xdp_userspace_prog"
)

var legacyDataplaneImportAllowlist = map[string]string{
	"cmd/xpfd/main.go":                         "backend selection, cleanup, and backend registration",
	"pkg/api/handlers.go":                      "REST handlers still reference legacy dataplane counters and types",
	"pkg/api/handlers_sessions.go":             "REST session reads still use legacy session types",
	"pkg/api/metrics.go":                       "Prometheus telemetry still reads legacy counters and metadata",
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
	"pkg/grpcapi/server_helpers.go":            "gRPC helpers still format legacy dataplane types and bridge runtime accessors",
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
}

var dpdkEBPFImportAllowlist = map[string]string{
	"pkg/dataplane/dpdk/manager.go": "legacy DataPlane Map method returns *ebpf.Map until DPDK migrates off root DataPlane",
}

var dpdkBackendImportAllowlist = map[string]string{
	"cmd/xpfd/main.go": "backend registration and cleanup entry point",
}

var userspaceShimAllowedMapTypes = map[string]ebpf.MapType{
	"dnat_table":                 ebpf.Hash,
	"userspace_bindings":         ebpf.Array,
	"userspace_cpumap":           ebpf.CPUMap,
	"userspace_ctrl":             ebpf.Array,
	"userspace_fallback_stats":   ebpf.Array,
	"userspace_heartbeat":        ebpf.Array,
	"userspace_ingress_ifaces":   ebpf.Hash,
	"userspace_interface_nat_v4": ebpf.Hash,
	"userspace_interface_nat_v6": ebpf.Hash,
	"userspace_local_v4":         ebpf.Hash,
	"userspace_local_v6":         ebpf.Hash,
	"userspace_sessions":         ebpf.Hash,
	"userspace_trace":            ebpf.Hash,
	"userspace_xsk_map":          ebpf.XSKMap,
}

var userspaceShimAllowedProgramTypes = map[string]ebpf.ProgramType{
	userspaceXDPEntryProgForCanary: ebpf.XDP,
}

var (
	rustMapAnnotationRE = regexp.MustCompile(`#\[\s*map\s*\(\s*name\s*=\s*"([^"]+)"\s*\)\s*\]`)
	rustXDPFunctionRE   = regexp.MustCompile(`#\[\s*xdp\s*\]\s*(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

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

	found := map[string]bool{}
	var violations []string
	for _, path := range productionGoFilesUnder(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "cmd"),
		filepath.Join(repoRootForBoundaryCanary, "pkg"),
	}) {
		rel := repoRelativePath(t, path)
		if strings.HasPrefix(rel, "pkg/dataplane/dpdk/") {
			continue
		}
		for _, imp := range importPaths(t, path) {
			if imp == dpdkBackendImportForCanary || strings.HasPrefix(imp, dpdkBackendImportForCanary+"/") {
				if _, ok := dpdkBackendImportAllowlist[rel]; ok {
					found[rel] = true
				} else {
					violations = append(violations, rel+" imports "+imp)
				}
			}
		}
	}

	var stale []string
	for rel := range dpdkBackendImportAllowlist {
		if !found[rel] {
			stale = append(stale, rel)
		}
	}

	if len(violations) > 0 || len(stale) > 0 {
		sort.Strings(violations)
		sort.Strings(stale)
		t.Fatalf(
			"DPDK backend import allowlist drift\nunexpected imports: %v\nstale allowlist entries: %v",
			violations,
			stale,
		)
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

func TestUserspaceXDPGenerateTargetStaysDecoupledFromLegacyBPF(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(makefileForCanary)
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	prereqs, recipe := makeTargetDefinition(t, string(data), "generate-userspace-xdp")
	if strings.TrimSpace(prereqs) != "" {
		t.Fatalf("generate-userspace-xdp must not depend on other Make targets, got prerequisites %q", prereqs)
	}
	if len(recipe) == 0 {
		t.Fatal("generate-userspace-xdp has no recipe")
	}
	body := strings.Join(recipe, "\n")
	for _, token := range []string{"generate", "-run", "build-userspace-xdp"} {
		if !strings.Contains(body, token) {
			t.Fatalf("generate-userspace-xdp recipe %q missing required token %q", body, token)
		}
	}
	for _, token := range []string{
		"bpf2go",
		"xdp_main",
		"tc_main",
		"bpf/xdp",
		"bpf/tc",
		"./pkg/dataplane/...",
		"generate-legacy-bpf",
		"$(MAKE)",
	} {
		if strings.Contains(body, token) {
			t.Fatalf("generate-userspace-xdp must not invoke legacy dataplane generation; recipe %q contains %q", body, token)
		}
	}
}

func TestUserspaceXDPGoGenerateRunSelectsOnlyShim(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("go", "generate", "-n", "-run", "^//go:generate bash build-userspace-xdp\\.sh$", "./pkg/dataplane")
	cmd.Dir = repoRootForBoundaryCanary
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go generate dry-run failed: %v\n%s", err, out)
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	if len(lines) != 1 || lines[0] != "bash build-userspace-xdp.sh" {
		t.Fatalf("go generate shim dry-run selected %v, want only build-userspace-xdp.sh", lines)
	}
}

func TestUserspaceShimCompileAdapterCoversCompilerDataplaneCalls(t *testing.T) {
	t.Parallel()

	compilerCalls := compilerDataplaneCalls(t)
	adapterMethods := receiverMethods(t, "loader.go", "userspaceShimCompileDataplane")
	allowedRealMethods := map[string]bool{
		"BumpFIBGeneration": true, // uses the shim-owned fib_gen_map
		"GetPersistentNAT":  true, // in-memory compatibility table
		"IsLoaded":          true, // lifecycle state only
	}

	var missing []string
	for name := range compilerCalls {
		if allowedRealMethods[name] || adapterMethods[name] {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("userspaceShimCompileDataplane must explicitly no-op or allow compiler DataPlane calls: %v", missing)
	}
}

func TestUserspaceShimSharedMapsAreExplicitCompatibilitySet(t *testing.T) {
	t.Parallel()

	specs := userspaceShimSharedMapSpecs()
	names := make(map[string]bool, len(specs))
	for _, spec := range specs {
		names[spec.Name] = true
	}
	for _, name := range []string{
		"sessions",
		"sessions_v6",
		"dnat_table",
		"dnat_table_v6",
		"fib_gen_map",
		"fabric_fwd",
		"rg_active",
		"ha_watchdog",
		"session_id_gen",
		"global_counters",
		"flood_counters",
		"policy_counters",
		"zone_counters",
		"filter_counters",
		"interface_counters",
		"nat_port_counters",
		"nat_rule_counters",
	} {
		if !names[name] {
			t.Fatalf("userspace shim shared map %q missing from explicit compatibility set", name)
		}
	}
	for _, forbidden := range []string{
		"xdp_progs",
		"tc_progs",
		"iface_zone_map",
		"zone_configs",
		"policy_rules",
		"tx_ports",
		"redirect_capable",
	} {
		if names[forbidden] {
			t.Fatalf("userspace shim shared maps must not retain legacy pipeline map %q", forbidden)
		}
	}
}

func TestUserspaceXDPShimSourceMatchesRetainedObjectAllowlist(t *testing.T) {
	t.Parallel()

	foundMaps := map[string]string{}
	foundPrograms := map[string]string{}
	var forbidden []string

	for _, path := range rustSourceFilesUnder(t, filepath.Join(repoRootForBoundaryCanary, "userspace-xdp", "src")) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read userspace XDP shim source %s: %v", path, err)
		}
		text := string(data)
		rel := repoRelativePath(t, path)
		for _, token := range []string{
			"ProgramArray",
			".tail_call(",
			"bpf_tail_call",
		} {
			if strings.Contains(text, token) {
				forbidden = append(forbidden, fmt.Sprintf("%s contains %q", rel, token))
			}
		}
		for _, match := range rustMapAnnotationRE.FindAllStringSubmatchIndex(text, -1) {
			name := text[match[2]:match[3]]
			foundMaps[name] = fmt.Sprintf("%s at %s:%d", name, rel, lineForOffset(text, match[0]))
		}
		for _, match := range rustXDPFunctionRE.FindAllStringSubmatchIndex(text, -1) {
			name := text[match[2]:match[3]]
			foundPrograms[name] = fmt.Sprintf("%s at %s:%d", name, rel, lineForOffset(text, match[0]))
		}
	}

	unexpectedMaps, missingMaps := compareStringSetToAllowed(foundMaps, keysOfMapTypeAllowlist(userspaceShimAllowedMapTypes))
	unexpectedPrograms, missingPrograms := compareStringSetToAllowed(foundPrograms, keysOfProgramTypeAllowlist(userspaceShimAllowedProgramTypes))
	if len(forbidden) > 0 || len(unexpectedMaps) > 0 || len(missingMaps) > 0 ||
		len(unexpectedPrograms) > 0 || len(missingPrograms) > 0 {
		sort.Strings(forbidden)
		sort.Strings(unexpectedMaps)
		sort.Strings(missingMaps)
		sort.Strings(unexpectedPrograms)
		sort.Strings(missingPrograms)
		t.Fatalf(
			"userspace XDP shim source allowlist drift\nforbidden tail-call tokens: %v\nunexpected maps: %v\nmissing maps: %v\nunexpected programs: %v\nmissing programs: %v",
			forbidden,
			unexpectedMaps,
			missingMaps,
			unexpectedPrograms,
			missingPrograms,
		)
	}
}

func TestUserspaceXDPShimObjectMatchesRetainedCollectionAllowlist(t *testing.T) {
	t.Parallel()

	spec, err := loadRustUserspaceXDP()
	if err != nil {
		t.Fatalf("load userspace XDP shim object: %v", err)
	}

	foundMaps := map[string]string{}
	var wrongMaps []string
	for name, mapSpec := range spec.Maps {
		foundMaps[name] = name
		if want, ok := userspaceShimAllowedMapTypes[name]; ok && mapSpec.Type != want {
			wrongMaps = append(wrongMaps, fmt.Sprintf("%s type %s, want %s", name, mapSpec.Type, want))
		}
	}
	foundPrograms := map[string]string{}
	var wrongPrograms []string
	for name, programSpec := range spec.Programs {
		foundPrograms[name] = name
		if want, ok := userspaceShimAllowedProgramTypes[name]; ok && programSpec.Type != want {
			wrongPrograms = append(wrongPrograms, fmt.Sprintf("%s type %s, want %s", name, programSpec.Type, want))
		}
	}

	unexpectedMaps, missingMaps := compareStringSetToAllowed(foundMaps, keysOfMapTypeAllowlist(userspaceShimAllowedMapTypes))
	unexpectedPrograms, missingPrograms := compareStringSetToAllowed(foundPrograms, keysOfProgramTypeAllowlist(userspaceShimAllowedProgramTypes))
	if len(wrongMaps) > 0 || len(unexpectedMaps) > 0 || len(missingMaps) > 0 ||
		len(wrongPrograms) > 0 || len(unexpectedPrograms) > 0 || len(missingPrograms) > 0 {
		sort.Strings(wrongMaps)
		sort.Strings(unexpectedMaps)
		sort.Strings(missingMaps)
		sort.Strings(wrongPrograms)
		sort.Strings(unexpectedPrograms)
		sort.Strings(missingPrograms)
		t.Fatalf(
			"userspace XDP shim object allowlist drift\nwrong map types: %v\nunexpected maps: %v\nmissing maps: %v\nwrong program types: %v\nunexpected programs: %v\nmissing programs: %v",
			wrongMaps,
			unexpectedMaps,
			missingMaps,
			wrongPrograms,
			unexpectedPrograms,
			missingPrograms,
		)
	}
}

func TestUserspaceManagerSelectsOnlyUserspaceXDPEntryProgram(t *testing.T) {
	t.Parallel()

	fset, files := productionGoPackageFilesUnder(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace"),
	})
	var violations []string
	for _, parsed := range files {
		rel := repoRelativePath(t, parsed.path)
		ast.Inspect(parsed.file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, rhs := range node.Rhs {
					if containsSwapXDPEntryProgMethodValue(rhs) {
						pos := fset.Position(rhs.Pos())
						violations = append(violations, fmt.Sprintf(
							"%s:%d captures SwapXDPEntryProg method value",
							rel,
							pos.Line,
						))
					}
				}
				for i, lhs := range node.Lhs {
					if !isXDPEntryProgField(lhs) {
						continue
					}
					var rhs ast.Expr
					if len(node.Rhs) == len(node.Lhs) {
						rhs = node.Rhs[i]
					}
					if !isUserspaceXDPEntryProgExpr(rhs) {
						pos := fset.Position(lhs.Pos())
						violations = append(violations, fmt.Sprintf(
							"%s:%d assigns XDPEntryProg from %q",
							rel,
							pos.Line,
							canaryExprString(rhs),
						))
					}
				}
			case *ast.CompositeLit:
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok || !isXDPEntryProgField(kv.Key) {
						continue
					}
					if !isUserspaceXDPEntryProgExpr(kv.Value) {
						pos := fset.Position(kv.Pos())
						violations = append(violations, fmt.Sprintf(
							"%s:%d initializes XDPEntryProg from %q",
							rel,
							pos.Line,
							canaryExprString(kv.Value),
						))
					}
				}
			case *ast.ValueSpec:
				for _, value := range node.Values {
					if containsSwapXDPEntryProgMethodValue(value) {
						pos := fset.Position(value.Pos())
						violations = append(violations, fmt.Sprintf(
							"%s:%d stores SwapXDPEntryProg method value",
							rel,
							pos.Line,
						))
					}
				}
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "SwapXDPEntryProg" {
					if len(node.Args) != 1 || !isUserspaceXDPEntryProgExpr(node.Args[0]) {
						var got string
						if len(node.Args) == 1 {
							got = canaryExprString(node.Args[0])
						}
						pos := fset.Position(node.Pos())
						violations = append(violations, fmt.Sprintf(
							"%s:%d calls SwapXDPEntryProg with %q",
							rel,
							pos.Line,
							got,
						))
					}
					return true
				}
				for _, arg := range node.Args {
					if containsSwapXDPEntryProgMethodValue(arg) {
						pos := fset.Position(arg.Pos())
						violations = append(violations, fmt.Sprintf(
							"%s:%d passes SwapXDPEntryProg method value",
							rel,
							pos.Line,
						))
					}
				}
			case *ast.ReturnStmt:
				for _, result := range node.Results {
					if containsSwapXDPEntryProgMethodValue(result) {
						pos := fset.Position(result.Pos())
						violations = append(violations, fmt.Sprintf(
							"%s:%d returns SwapXDPEntryProg method value",
							rel,
							pos.Line,
						))
					}
				}
			case *ast.UnaryExpr:
				if node.Op == token.AND && containsXDPEntryProgField(node.X) {
					pos := fset.Position(node.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d takes XDPEntryProg address",
						rel,
						pos.Line,
					))
				}
			}
			return true
		})
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("userspace manager production code must only select userspaceXDPEntryProg: %v", violations)
	}
}

func TestUserspaceXDPEntryProgramConstantNamesRetainedShim(t *testing.T) {
	t.Parallel()

	fset, files := productionGoPackageFilesUnder(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace"),
	})
	var found []string
	var violations []string
	for _, parsed := range files {
		ast.Inspect(parsed.file, func(n ast.Node) bool {
			valueSpec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, name := range valueSpec.Names {
				if name.Name != "userspaceXDPEntryProg" {
					continue
				}
				pos := fset.Position(name.Pos())
				location := fmt.Sprintf("%s:%d", repoRelativePath(t, parsed.path), pos.Line)
				found = append(found, location)
				if len(valueSpec.Values) != len(valueSpec.Names) {
					violations = append(violations, location+" uses implicit or tuple value")
					continue
				}
				lit, ok := valueSpec.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || lit.Value != strconv.Quote(userspaceXDPEntryProgForCanary) {
					violations = append(violations, fmt.Sprintf(
						"%s sets userspaceXDPEntryProg to %q, want %q",
						location,
						canaryExprString(valueSpec.Values[i]),
						userspaceXDPEntryProgForCanary,
					))
				}
			}
			return true
		})
	}
	if len(found) != 1 || len(violations) > 0 {
		sort.Strings(found)
		sort.Strings(violations)
		t.Fatalf("userspaceXDPEntryProg constant drift\nfound: %v\nviolations: %v", found, violations)
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

func compilerDataplaneCalls(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("compiler*.go")
	if err != nil {
		t.Fatalf("glob compiler files: %v", err)
	}
	out := make(map[string]bool)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "dp" {
				return true
			}
			out[sel.Sel.Name] = true
			return true
		})
	}
	return out
}

func receiverMethods(t *testing.T, path, receiverName string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		if receiverTypeName(fn.Recv.List[0].Type) == receiverName {
			out[fn.Name.Name] = true
		}
	}
	return out
}

func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return receiverTypeName(e.X)
	default:
		return ""
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

type canaryParsedGoFile struct {
	path string
	file *ast.File
}

func productionGoPackageFilesUnder(t *testing.T, roots []string) (*token.FileSet, []canaryParsedGoFile) {
	t.Helper()

	fset := token.NewFileSet()
	packageFiles := map[string]*ast.File{}
	var files []canaryParsedGoFile
	for _, path := range productionGoFilesUnder(t, roots) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		packageFiles[path] = file
		files = append(files, canaryParsedGoFile{path: path, file: file})
	}
	// NewPackage resolves same-package identifiers across files. It also reports
	// unrelated predeclared/imported identifiers because this canary does not
	// provide a full importer or universe scope, so the error is intentionally
	// ignored after the resolver has linked package-level objects.
	_, _ = ast.NewPackage(fset, packageFiles, nil, nil)
	return fset, files
}

func rustSourceFilesUnder(t *testing.T, root string) []string {
	t.Helper()

	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".rs") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk Rust source under %s: %v", root, err)
	}
	sort.Strings(files)
	return files
}

func compareStringSetToAllowed(found map[string]string, allowed map[string]bool) ([]string, []string) {
	var unexpected []string
	for name, location := range found {
		if !allowed[name] {
			unexpected = append(unexpected, location)
		}
	}
	var missing []string
	for name := range allowed {
		if _, ok := found[name]; !ok {
			missing = append(missing, name)
		}
	}
	return unexpected, missing
}

func keysOfMapTypeAllowlist(values map[string]ebpf.MapType) map[string]bool {
	keys := make(map[string]bool, len(values))
	for name := range values {
		keys[name] = true
	}
	return keys
}

func keysOfProgramTypeAllowlist(values map[string]ebpf.ProgramType) map[string]bool {
	keys := make(map[string]bool, len(values))
	for name := range values {
		keys[name] = true
	}
	return keys
}

func lineForOffset(text string, offset int) int {
	if offset > len(text) {
		offset = len(text)
	}
	return strings.Count(text[:offset], "\n") + 1
}

func isXDPEntryProgField(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "XDPEntryProg"
	case *ast.SelectorExpr:
		return e.Sel.Name == "XDPEntryProg"
	default:
		return false
	}
}

func isUserspaceXDPEntryProgExpr(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok || ident.Name != "userspaceXDPEntryProg" {
		return false
	}
	return ident.Obj != nil && ident.Obj.Kind == ast.Con
}

func containsXDPEntryProgField(expr ast.Expr) bool {
	return containsExpr(expr, isXDPEntryProgField)
}

func containsSwapXDPEntryProgMethodValue(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	var found bool
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "SwapXDPEntryProg" {
				for _, arg := range node.Args {
					if containsSwapXDPEntryProgMethodValue(arg) {
						found = true
						return false
					}
				}
				return false
			}
		case *ast.SelectorExpr:
			if node.Sel.Name == "SwapXDPEntryProg" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func containsExpr(expr ast.Expr, match func(ast.Expr) bool) bool {
	if expr == nil {
		return false
	}
	var found bool
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		expr, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		if match(expr) {
			found = true
			return false
		}
		return true
	})
	return found
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

func makeTargetDefinition(t *testing.T, makefile, target string) (string, []string) {
	t.Helper()

	lines := strings.Split(makefile, "\n")
	for i, line := range lines {
		targets, prereqs, ok := parseMakeTargetLine(line)
		if !ok {
			continue
		}
		found := false
		for _, name := range targets {
			if name == target {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		var recipe []string
		for _, next := range lines[i+1:] {
			trimmed := strings.TrimSpace(next)
			switch {
			case strings.HasPrefix(next, "\t"):
				recipe = append(recipe, strings.TrimSpace(next))
			case trimmed == "" || strings.HasPrefix(trimmed, "#"):
				if len(recipe) == 0 {
					continue
				}
				return prereqs, recipe
			default:
				return prereqs, recipe
			}
		}
		return prereqs, recipe
	}
	t.Fatalf("Makefile target %q not found", target)
	return "", nil
}

func parseMakeTargetLine(line string) ([]string, string, bool) {
	if strings.HasPrefix(line, "\t") {
		return nil, "", false
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, "", false
	}
	idx := strings.Index(trimmed, ":")
	if idx < 0 {
		return nil, "", false
	}
	targets := strings.Fields(strings.TrimSpace(trimmed[:idx]))
	if len(targets) == 0 || targets[0] == ".PHONY" {
		return nil, "", false
	}
	return targets, strings.TrimSpace(trimmed[idx+1:]), true
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
	case *ast.BasicLit:
		return e.Value
	default:
		return ""
	}
}
