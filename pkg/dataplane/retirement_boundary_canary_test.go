package dataplane

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	rustMapAnnotationRE = regexp.MustCompile(`#\[\s*map\s*\([^)]*\bname\s*=\s*"([^"]+)"[^)]*\)\s*\]`)
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

	violations := userspaceXDPEntryProgramViolations(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace"),
	})
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("userspace manager production code must only select userspaceXDPEntryProg: %v", violations)
	}
}

func TestBPFShimEntryProgramStateIsNotJSONMutable(t *testing.T) {
	t.Parallel()

	if userspaceShimEntryProg != userspaceXDPEntryProgForCanary {
		t.Fatalf(
			"userspace shim entry-program constant = %q, want %q",
			userspaceShimEntryProg,
			userspaceXDPEntryProgForCanary,
		)
	}

	managerType := reflect.TypeOf(Manager{})
	if _, ok := managerType.FieldByName("XDPEntryProg"); ok {
		t.Fatal("dataplane.Manager must not export XDPEntryProg")
	}
	field, ok := managerType.FieldByName("xdpEntryProg")
	if !ok {
		t.Fatal("dataplane.Manager lost xdpEntryProg state field")
	}
	if field.PkgPath == "" {
		t.Fatal("dataplane.Manager.xdpEntryProg must stay unexported")
	}

	managerPtrType := reflect.TypeOf((*Manager)(nil))
	if _, ok := managerPtrType.MethodByName("SwapXDPEntryProg"); ok {
		t.Fatal("dataplane.Manager must not expose arbitrary SwapXDPEntryProg")
	}
	if _, ok := managerPtrType.MethodByName("SwapToUserspaceXDPShimEntryProgram"); !ok {
		t.Fatal("dataplane.Manager lost narrow userspace shim swap method")
	}

	data, err := json.Marshal(&Manager{xdpEntryProg: "xdp_bypassed"})
	if err != nil {
		t.Fatalf("marshal Manager: %v", err)
	}
	if strings.Contains(string(data), "xdp_bypassed") ||
		strings.Contains(string(data), "XDPEntryProg") ||
		strings.Contains(string(data), "xdpEntryProg") {
		t.Fatalf("xdpEntryProg leaked into JSON: %s", data)
	}

	var decoded Manager
	if err := json.Unmarshal(
		[]byte(`{"XDPEntryProg":"xdp_bypassed","xdpEntryProg":"xdp_bypassed"}`),
		&decoded,
	); err != nil {
		t.Fatalf("unmarshal Manager: %v", err)
	}
	if got := decoded.XDPEntryProgram(); got == "xdp_bypassed" {
		t.Fatalf("JSON mutated xdpEntryProg to %q", got)
	}
}

func TestUserspaceManagerDoesNotImportReflectOrUnsafe(t *testing.T) {
	t.Parallel()

	var violations []string
	for _, path := range productionGoFilesUnder(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace"),
	}) {
		rel := repoRelativePath(t, path)
		for _, imp := range importPaths(t, path) {
			switch imp {
			case "reflect", "unsafe":
				violations = append(violations, rel+" imports "+imp)
			}
		}
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("userspace production code must not use reflection/unsafe to bypass entry-program canaries: %v", violations)
	}
}

func TestUserspaceXDPEntryProgramConstantNamesRetainedShim(t *testing.T) {
	t.Parallel()

	found, violations := userspaceXDPEntryProgramConstantDrift(t, []string{
		filepath.Join(repoRootForBoundaryCanary, "pkg", "dataplane", "userspace"),
	})
	if len(found) != 1 || len(violations) > 0 {
		sort.Strings(found)
		sort.Strings(violations)
		t.Fatalf("userspaceXDPEntryProg constant drift\nfound: %v\nviolations: %v", found, violations)
	}
}

func TestUserspaceEntryProgramCanaryAllowsCrossFileConstantFixture(t *testing.T) {
	t.Parallel()

	root := writeUserspaceEntryProgramFixture(t, map[string]string{
		"const.go": `
package userspace

const userspaceXDPEntryProg = "xdp_userspace_prog"

type shim struct{}
func (s *shim) SelectUserspaceXDPShimEntryProgram() {}
func (s *shim) SwapToUserspaceXDPShimEntryProgram() error { return nil }
type manager struct { bpfShim *shim }
`,
		"use.go": `
package userspace

func valid(m *manager) {
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	_ = m.bpfShim.SwapToUserspaceXDPShimEntryProgram()
}
`,
	})

	if got := userspaceXDPEntryProgramViolations(t, []string{root}); len(got) > 0 {
		t.Fatalf("valid cross-file constant fixture produced violations: %v", got)
	}
	found, drift := userspaceXDPEntryProgramConstantDrift(t, []string{root})
	if len(found) != 1 || len(drift) > 0 {
		t.Fatalf("valid cross-file constant drift\nfound: %v\nviolations: %v", found, drift)
	}
}

func TestUserspaceEntryProgramCanaryRejectsBypassFixtures(t *testing.T) {
	t.Parallel()

	base := `
package userspace

const userspaceXDPEntryProg = "xdp_userspace_prog"

type shim struct { XDPEntryProg string }
func (s *shim) SwapXDPEntryProg(name string) error { return nil }
type manager struct { bpfShim *shim }
func consume(v interface{}) {}
`

	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "literal_assignment",
			body: `
package userspace

func literalAssign(m *manager) {
	m.bpfShim.XDPEntryProg = "xdp_main_prog"
}
`,
			want: []string{"assigns XDPEntryProg from", "xdp_main_prog"},
		},
		{
			name: "shadowed_constant_name",
			body: `
package userspace

func shadowedConstName(m *manager) {
	userspaceXDPEntryProg := "xdp_main_prog"
	m.bpfShim.XDPEntryProg = userspaceXDPEntryProg
}
`,
			want: []string{"assigns XDPEntryProg from \"userspaceXDPEntryProg\""},
		},
		{
			name: "pointer_alias",
			body: `
package userspace

func pointerAlias(m *manager) {
	p := &m.bpfShim.XDPEntryProg
	_ = p
}
`,
			want: []string{"takes XDPEntryProg address"},
		},
		{
			name: "method_value_capture",
			body: `
package userspace

func methodValueCapture(m *manager) {
	swap := m.bpfShim.SwapXDPEntryProg
	_ = swap
}
`,
			want: []string{"captures SwapXDPEntryProg method value"},
		},
		{
			name: "method_value_pass",
			body: `
package userspace

func methodValuePass(m *manager) {
	consume(m.bpfShim.SwapXDPEntryProg)
}
`,
			want: []string{"passes SwapXDPEntryProg method value"},
		},
		{
			name: "method_value_return",
			body: `
package userspace

func methodValueReturn(m *manager) func(string) error {
	return m.bpfShim.SwapXDPEntryProg
}
`,
			want: []string{"returns SwapXDPEntryProg method value"},
		},
		{
			name: "direct_bad_call",
			body: `
package userspace

func directBadCall(m *manager) {
	_ = m.bpfShim.SwapXDPEntryProg("xdp_main_prog")
}
`,
			want: []string{"calls SwapXDPEntryProg with", "xdp_main_prog"},
		},
		{
			name: "parenthesized_bad_call",
			body: `
package userspace

func parenBadCall(m *manager) {
	_ = (m.bpfShim.SwapXDPEntryProg)("xdp_main_prog")
}
`,
			want: []string{"calls SwapXDPEntryProg with", "xdp_main_prog"},
		},
		{
			name: "method_expression_bad_call",
			body: `
package userspace

func methodExprBadCall(m *manager) {
	_ = ((*shim).SwapXDPEntryProg)(m.bpfShim, "xdp_main_prog")
}
`,
			want: []string{"calls SwapXDPEntryProg with", "xdp_main_prog"},
		},
		{
			name: "raw_string_bad_call",
			body: `
package userspace

func rawStringBadCall(m *manager) {
	_ = m.bpfShim.SwapXDPEntryProg(` + "`xdp_main_prog`" + `)
}
`,
			want: []string{"calls SwapXDPEntryProg with", "xdp_main_prog"},
		},
		{
			name: "slice_index_bad_call",
			body: `
package userspace

func sliceIndexBadCall(m *manager) {
	_ = ([]func(string) error{m.bpfShim.SwapXDPEntryProg})[0]("xdp_main_prog")
}
`,
			want: []string{"calls through SwapXDPEntryProg method value"},
		},
		{
			name: "double_parenthesized_bad_call",
			body: `
package userspace

func doubleParenBadCall(m *manager) {
	_ = ((m.bpfShim.SwapXDPEntryProg))("xdp_main_prog")
}
`,
			want: []string{"calls SwapXDPEntryProg with", "xdp_main_prog"},
		},
		{
			name: "wrapped_method_value_callee",
			body: `
package userspace

func wrap(fn func(string) error) func(string) error { return fn }
func wrappedMethodValueCallee(m *manager) {
	_ = wrap(m.bpfShim.SwapXDPEntryProg)(userspaceXDPEntryProg)
}
`,
			want: []string{"calls through SwapXDPEntryProg method value"},
		},
		{
			name: "send_stmt_method_value",
			body: `
package userspace

func sendStmtBypass(m *manager) {
	ch := make(chan func(string) error, 1)
	ch <- m.bpfShim.SwapXDPEntryProg
}
`,
			want: []string{"sends SwapXDPEntryProg method value"},
		},
		{
			name: "range_stmt_method_value",
			body: `
package userspace

func rangeStmtBypass(m *manager) {
	for _, fn := range []func(string) error{m.bpfShim.SwapXDPEntryProg} {
		_ = fn(userspaceXDPEntryProg)
	}
}
`,
			want: []string{"ranges over SwapXDPEntryProg method value"},
		},
		{
			name: "map_key_method_value",
			body: `
package userspace

func mapKeyBypass(m *manager) {
	mapOfFuncs := make(map[any]bool)
	mapOfFuncs[m.bpfShim.SwapXDPEntryProg] = true
}
`,
			want: []string{"uses SwapXDPEntryProg method value"},
		},
		{
			name: "switch_tag_method_value",
			body: `
package userspace

func switchTagBypass(m *manager) {
	switch m.bpfShim.SwapXDPEntryProg {
	case nil:
	default:
	}
}
`,
			want: []string{"switches on SwapXDPEntryProg method value"},
		},
		{
			name: "json_unmarshal_bpf_shim",
			body: `
package userspace

import "encoding/json"

func jsonBypass(m *manager) {
	_ = json.Unmarshal([]byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_dot_import_unmarshal_bpf_shim",
			body: `
package userspace

import . "encoding/json"

func jsonDotImportBypass(m *manager) {
	_ = Unmarshal([]byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_new_decoder_decode_bpf_shim",
			body: `
package userspace

import (
	"encoding/json"
	"strings"
)

func jsonDecoderBypass(m *manager) {
	_ = json.NewDecoder(strings.NewReader(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `)).Decode(m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_dot_import_new_decoder_decode_bpf_shim",
			body: `
package userspace

import (
	. "encoding/json"
	"strings"
)

func jsonDotDecoderBypass(m *manager) {
	_ = NewDecoder(strings.NewReader(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `)).Decode(m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_unmarshal_alias_bpf_shim",
			body: `
package userspace

import "encoding/json"

func jsonUnmarshalAliasBypass(m *manager) {
	alias := m.bpfShim
	_ = json.Unmarshal([]byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), alias)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_new_decoder_alias_bpf_shim",
			body: `
package userspace

import (
	"encoding/json"
	"strings"
)

func jsonDecodeAliasBypass(m *manager) {
	alias := m.bpfShim
	_ = json.NewDecoder(strings.NewReader(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `)).Decode(alias)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_stored_decoder_decode_bpf_shim",
			body: `
package userspace

import (
	"encoding/json"
	"strings"
)

func jsonStoredDecoderBypass(m *manager) {
	dec := json.NewDecoder(strings.NewReader(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `))
	_ = dec.Decode(m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_func_var_unmarshal_bpf_shim",
			body: `
package userspace

import "encoding/json"

func jsonFuncVarBypass(m *manager) {
	decode := json.Unmarshal
	_ = decode([]byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_tuple_spread_bpf_shim",
			body: `
package userspace

import "encoding/json"

func tupleDecodeArgs(m *manager) ([]byte, *bpfShim) {
	return []byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), m.bpfShim
}

func jsonTupleSpreadBypass(m *manager) {
	_ = json.Unmarshal(tupleDecodeArgs(m))
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "json_v2_unmarshal_bpf_shim",
			body: `
package userspace

import "encoding/json/v2"

func jsonV2Bypass(m *manager) {
	_ = json.Unmarshal([]byte(` + "`{\"XDPEntryProg\":\"xdp_bypassed\"}`" + `), m.bpfShim)
}
`,
			want: []string{"encoding/json decode into bpfShim"},
		},
		{
			name: "reflection_field_name",
			body: `
package userspace

func reflectionName() {
	_ = "XDPEntryProg"
}
`,
			want: []string{"uses XDPEntryProg string literal"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := writeUserspaceEntryProgramFixture(t, map[string]string{
				"base.go":   base,
				"bypass.go": tc.body,
			})
			violations := userspaceXDPEntryProgramViolations(t, []string{root})
			assertCanaryViolationContains(t, violations, tc.want...)
		})
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

type canaryParsedGoFile struct {
	path string
	file *ast.File
}

func userspaceXDPEntryProgramViolations(t *testing.T, roots []string) []string {
	t.Helper()

	fset, files := productionGoPackageFilesUnder(t, roots)
	var violations []string
	for _, parsed := range files {
		rel := repoRelativePath(t, parsed.path)
		parents := astParentMap(parsed.file)
		jsonImports, jsonDotImport := importNamesForPath(parsed.file, "encoding/json")
		jsonV2Imports, jsonV2DotImport := importNamesForPath(parsed.file, "encoding/json/v2")
		for name := range jsonV2Imports {
			jsonImports[name] = true
		}
		jsonDotImport = jsonDotImport || jsonV2DotImport
		ast.Inspect(parsed.file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					if !isXDPEntryProgField(lhs) {
						continue
					}
					var rhs ast.Expr
					if len(node.Rhs) == len(node.Lhs) {
						rhs = node.Rhs[i]
					}
					pos := fset.Position(lhs.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d assigns XDPEntryProg from %q",
						rel,
						pos.Line,
						canaryExprString(rhs),
					))
				}
			case *ast.CompositeLit:
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok || !isXDPEntryProgField(kv.Key) {
						continue
					}
					pos := fset.Position(kv.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d initializes XDPEntryProg from %q",
						rel,
						pos.Line,
						canaryExprString(kv.Value),
					))
				}
			case *ast.CallExpr:
				if isJSONDecoderIntoBPFShim(node, jsonImports, jsonDotImport) {
					pos := fset.Position(node.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d encoding/json decode into bpfShim can mutate XDPEntryProg",
						rel,
						pos.Line,
					))
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
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(node.Value)
				if err == nil && value == "XDPEntryProg" {
					pos := fset.Position(node.Pos())
					violations = append(violations, fmt.Sprintf(
						"%s:%d uses XDPEntryProg string literal",
						rel,
						pos.Line,
					))
				}
			case *ast.SelectorExpr:
				if node.Sel.Name != "SwapXDPEntryProg" {
					return true
				}
				if violation := swapXDPEntryProgSelectorViolation(node, parents, fset, rel); violation != "" {
					violations = append(violations, violation)
				}
			}
			return true
		})
	}
	sort.Strings(violations)
	return violations
}

func userspaceXDPEntryProgramConstantDrift(t *testing.T, roots []string) ([]string, []string) {
	t.Helper()

	fset, files := productionGoPackageFilesUnder(t, roots)
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
	sort.Strings(found)
	sort.Strings(violations)
	return found, violations
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
	resolveUserspaceXDPEntryProgramIdents(packageFiles)
	return fset, files
}

func astParentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	return parents
}

func importNamesForPath(file *ast.File, importPath string) (map[string]bool, bool) {
	names := map[string]bool{}
	dotImport := false
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "." {
				dotImport = true
			}
			if imp.Name.Name != "_" && imp.Name.Name != "." {
				names[imp.Name.Name] = true
			}
			continue
		}
		names[defaultImportName(importPath)] = true
	}
	return names, dotImport
}

func defaultImportName(importPath string) string {
	last := importPath
	if idx := strings.LastIndex(last, "/"); idx >= 0 {
		last = last[idx+1:]
	}
	if strings.HasPrefix(last, "v") && len(last) > 1 {
		allDigits := true
		for _, r := range last[1:] {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			trimmed := strings.TrimSuffix(importPath, "/"+last)
			if idx := strings.LastIndex(trimmed, "/"); idx >= 0 {
				return trimmed[idx+1:]
			}
			return trimmed
		}
	}
	if idx := strings.LastIndex(importPath, "/"); idx >= 0 {
		return importPath[idx+1:]
	}
	return importPath
}

func resolveUserspaceXDPEntryProgramIdents(files map[string]*ast.File) {
	var packageConst *ast.Object
	for _, file := range files {
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.CONST {
				continue
			}
			for _, spec := range genDecl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range valueSpec.Names {
					if name.Name == "userspaceXDPEntryProg" && name.Obj != nil && name.Obj.Kind == ast.Con {
						packageConst = name.Obj
					}
				}
			}
		}
	}
	if packageConst == nil {
		return
	}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if ok && ident.Name == "userspaceXDPEntryProg" && ident.Obj == nil {
				ident.Obj = packageConst
			}
			return true
		})
	}
}

func writeUserspaceEntryProgramFixture(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", path, err)
		}
	}
	return root
}

func assertCanaryViolationContains(t *testing.T, violations []string, needles ...string) {
	t.Helper()

	for _, violation := range violations {
		matches := true
		for _, needle := range needles {
			if !strings.Contains(violation, needle) {
				matches = false
				break
			}
		}
		if matches {
			return
		}
	}
	t.Fatalf("no violation contains all of %q\nall violations:\n%s", needles, strings.Join(violations, "\n"))
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

func isJSONDecoderIntoBPFShim(call *ast.CallExpr, jsonImports map[string]bool, jsonDotImport bool) bool {
	if (len(jsonImports) == 0 && !jsonDotImport) || len(call.Args) == 0 {
		return false
	}

	if isJSONUnmarshalCallee(call.Fun, jsonImports, jsonDotImport) {
		switch len(call.Args) {
		case 0:
			return false
		case 1:
			return callReturnsBPFShimTuple(call.Args[0], map[*ast.Object]bool{})
		default:
			return containsBPFShimReference(call.Args[1])
		}
	}

	if len(call.Args) != 1 {
		return false
	}
	if sel, ok := unparenExpr(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Decode" {
		if !isJSONNewDecoderReceiver(sel.X, jsonImports, jsonDotImport, map[*ast.Object]bool{}) {
			return false
		}
		return containsBPFShimReference(call.Args[0])
	}
	return false
}

func isJSONUnmarshalCallee(expr ast.Expr, jsonImports map[string]bool, jsonDotImport bool) bool {
	switch fun := unparenExpr(expr).(type) {
	case *ast.SelectorExpr:
		pkg, ok := unparenExpr(fun.X).(*ast.Ident)
		return ok && fun.Sel.Name == "Unmarshal" && jsonImports[pkg.Name]
	case *ast.Ident:
		if jsonDotImport && fun.Name == "Unmarshal" {
			return true
		}
		return identResolvesToJSONUnmarshal(fun, jsonImports, jsonDotImport, map[*ast.Object]bool{})
	default:
		return false
	}
}

func identResolvesToJSONUnmarshal(ident *ast.Ident, jsonImports map[string]bool, jsonDotImport bool, seen map[*ast.Object]bool) bool {
	if ident == nil || ident.Obj == nil {
		return false
	}
	obj := ident.Obj
	if seen[obj] {
		return false
	}
	seen[obj] = true
	defer delete(seen, obj)

	switch decl := obj.Decl.(type) {
	case *ast.AssignStmt:
		if len(decl.Rhs) != len(decl.Lhs) {
			return false
		}
		for i, lhs := range decl.Lhs {
			lhsIdent, ok := lhs.(*ast.Ident)
			if ok && lhsIdent.Obj == obj {
				return isJSONUnmarshalCallee(decl.Rhs[i], jsonImports, jsonDotImport)
			}
		}
	case *ast.ValueSpec:
		if len(decl.Values) != len(decl.Names) {
			return false
		}
		for i, name := range decl.Names {
			if name.Obj == obj {
				return isJSONUnmarshalCallee(decl.Values[i], jsonImports, jsonDotImport)
			}
		}
	}
	return false
}

func isJSONNewDecoderReceiver(expr ast.Expr, jsonImports map[string]bool, jsonDotImport bool, seen map[*ast.Object]bool) bool {
	switch e := unparenExpr(expr).(type) {
	case *ast.CallExpr:
		return isJSONNewDecoderCall(e, jsonImports, jsonDotImport)
	case *ast.Ident:
		return identResolvesToJSONNewDecoder(e, jsonImports, jsonDotImport, seen)
	default:
		return false
	}
}

func isJSONNewDecoderCall(call *ast.CallExpr, jsonImports map[string]bool, jsonDotImport bool) bool {
	if call == nil {
		return false
	}
	switch fun := unparenExpr(call.Fun).(type) {
	case *ast.SelectorExpr:
		pkg, ok := unparenExpr(fun.X).(*ast.Ident)
		return ok && fun.Sel.Name == "NewDecoder" && jsonImports[pkg.Name]
	case *ast.Ident:
		return jsonDotImport && fun.Name == "NewDecoder"
	default:
		return false
	}
}

func identResolvesToJSONNewDecoder(ident *ast.Ident, jsonImports map[string]bool, jsonDotImport bool, seen map[*ast.Object]bool) bool {
	if ident == nil || ident.Obj == nil {
		return false
	}
	obj := ident.Obj
	if seen[obj] {
		return false
	}
	seen[obj] = true
	defer delete(seen, obj)

	switch decl := obj.Decl.(type) {
	case *ast.AssignStmt:
		if len(decl.Rhs) != len(decl.Lhs) {
			return false
		}
		for i, lhs := range decl.Lhs {
			lhsIdent, ok := lhs.(*ast.Ident)
			if ok && lhsIdent.Obj == obj {
				return isJSONNewDecoderReceiver(decl.Rhs[i], jsonImports, jsonDotImport, seen)
			}
		}
	case *ast.ValueSpec:
		if len(decl.Values) != len(decl.Names) {
			return false
		}
		for i, name := range decl.Names {
			if name.Obj == obj {
				return isJSONNewDecoderReceiver(decl.Values[i], jsonImports, jsonDotImport, seen)
			}
		}
	}
	return false
}

func callReturnsBPFShimTuple(expr ast.Expr, seen map[*ast.Object]bool) bool {
	call, ok := unparenExpr(expr).(*ast.CallExpr)
	if !ok {
		return false
	}

	switch fun := unparenExpr(call.Fun).(type) {
	case *ast.FuncLit:
		return blockReturnsBPFShimTuple(fun.Body, seen)
	case *ast.Ident:
		return identReturnsBPFShimTuple(fun, seen)
	default:
		return false
	}
}

func identReturnsBPFShimTuple(ident *ast.Ident, seen map[*ast.Object]bool) bool {
	if ident == nil || ident.Obj == nil {
		return false
	}
	obj := ident.Obj
	if seen[obj] {
		return false
	}
	seen[obj] = true
	defer delete(seen, obj)

	switch decl := obj.Decl.(type) {
	case *ast.FuncDecl:
		return blockReturnsBPFShimTuple(decl.Body, seen)
	case *ast.AssignStmt:
		if len(decl.Rhs) != len(decl.Lhs) {
			return false
		}
		for i, lhs := range decl.Lhs {
			lhsIdent, ok := lhs.(*ast.Ident)
			if ok && lhsIdent.Obj == obj {
				return callReturnsBPFShimTuple(decl.Rhs[i], seen)
			}
		}
	case *ast.ValueSpec:
		if len(decl.Values) != len(decl.Names) {
			return false
		}
		for i, name := range decl.Names {
			if name.Obj == obj {
				return callReturnsBPFShimTuple(decl.Values[i], seen)
			}
		}
	}
	return false
}

func blockReturnsBPFShimTuple(block *ast.BlockStmt, seen map[*ast.Object]bool) bool {
	if block == nil {
		return false
	}
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, result := range ret.Results {
			if containsBPFShimReferenceExpr(result, seen) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func containsBPFShimSelector(expr ast.Expr) bool {
	return containsExpr(expr, func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "bpfShim"
	})
}

func containsBPFShimReference(expr ast.Expr) bool {
	return containsBPFShimReferenceExpr(expr, map[*ast.Object]bool{})
}

func containsBPFShimReferenceExpr(expr ast.Expr, seen map[*ast.Object]bool) bool {
	if expr == nil {
		return false
	}
	if containsBPFShimSelector(expr) {
		return true
	}

	switch e := unparenExpr(expr).(type) {
	case *ast.Ident:
		return containsBPFShimFromIdent(e, seen)
	case *ast.SelectorExpr:
		return containsBPFShimReferenceExpr(e.X, seen)
	case *ast.StarExpr:
		return containsBPFShimReferenceExpr(e.X, seen)
	case *ast.UnaryExpr:
		return containsBPFShimReferenceExpr(e.X, seen)
	case *ast.IndexExpr:
		return containsBPFShimReferenceExpr(e.X, seen) || containsBPFShimReferenceExpr(e.Index, seen)
	case *ast.IndexListExpr:
		if containsBPFShimReferenceExpr(e.X, seen) {
			return true
		}
		for _, idx := range e.Indices {
			if containsBPFShimReferenceExpr(idx, seen) {
				return true
			}
		}
	}

	return false
}

func containsBPFShimFromIdent(ident *ast.Ident, seen map[*ast.Object]bool) bool {
	if ident == nil || ident.Obj == nil {
		return false
	}
	obj := ident.Obj
	if seen[obj] {
		return false
	}
	seen[obj] = true
	defer delete(seen, obj)

	switch decl := obj.Decl.(type) {
	case *ast.AssignStmt:
		if len(decl.Rhs) != len(decl.Lhs) {
			return false
		}
		for i, lhs := range decl.Lhs {
			lhsIdent, ok := lhs.(*ast.Ident)
			if ok && lhsIdent.Obj == obj {
				return containsBPFShimReferenceExpr(decl.Rhs[i], seen)
			}
		}
	case *ast.ValueSpec:
		if len(decl.Values) != len(decl.Names) {
			return false
		}
		for i, name := range decl.Names {
			if name.Obj == obj {
				return containsBPFShimReferenceExpr(decl.Values[i], seen)
			}
		}
	}

	return false
}

func swapXDPEntryProgSelectorViolation(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node, fset *token.FileSet, rel string) string {
	if call, methodExpr, ok := enclosingDirectSwapXDPEntryProgCall(sel, parents); ok {
		argIndex := 0
		if methodExpr {
			argIndex = 1
		}
		var got string
		if len(call.Args) > argIndex {
			got = canaryExprString(call.Args[argIndex])
		}
		pos := fset.Position(call.Pos())
		return fmt.Sprintf("%s:%d calls SwapXDPEntryProg with %q", rel, pos.Line, got)
	}

	pos := fset.Position(sel.Pos())
	return fmt.Sprintf("%s:%d %s", rel, pos.Line, swapXDPEntryProgMethodValueContext(sel, parents))
}

func enclosingDirectSwapXDPEntryProgCall(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node) (*ast.CallExpr, bool, bool) {
	var expr ast.Node = sel
	for {
		parent := parents[expr]
		if paren, ok := parent.(*ast.ParenExpr); ok && paren.X == expr {
			expr = paren
			continue
		}
		call, ok := parent.(*ast.CallExpr)
		if !ok || call.Fun != expr {
			return nil, false, false
		}
		return call, isSwapXDPEntryProgMethodExpression(sel), true
	}
}

func isSwapXDPEntryProgMethodExpression(sel *ast.SelectorExpr) bool {
	_, ok := unparenExpr(sel.X).(*ast.StarExpr)
	return ok
}

func swapXDPEntryProgMethodValueContext(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node) string {
	if selectorInsideCallFun(sel, parents) {
		return "calls through SwapXDPEntryProg method value"
	}

	for child := ast.Node(sel); child != nil; {
		parent := parents[child]
		switch node := parent.(type) {
		case *ast.AssignStmt:
			if exprListContainsNode(node.Rhs, child) {
				return "captures SwapXDPEntryProg method value"
			}
		case *ast.ValueSpec:
			if exprListContainsNode(node.Values, child) {
				return "stores SwapXDPEntryProg method value"
			}
		case *ast.ReturnStmt:
			if exprListContainsNode(node.Results, child) {
				return "returns SwapXDPEntryProg method value"
			}
		case *ast.CallExpr:
			if exprListContainsNode(node.Args, child) {
				return "passes SwapXDPEntryProg method value"
			}
		case *ast.SendStmt:
			if node.Value == child {
				return "sends SwapXDPEntryProg method value"
			}
		case *ast.RangeStmt:
			if node.X == child {
				return "ranges over SwapXDPEntryProg method value"
			}
		case *ast.SwitchStmt:
			if node.Tag == child {
				return "switches on SwapXDPEntryProg method value"
			}
		}
		child = parent
	}
	return "uses SwapXDPEntryProg method value"
}

func selectorInsideCallFun(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node) bool {
	for child := ast.Node(sel); child != nil; {
		parent := parents[child]
		if call, ok := parent.(*ast.CallExpr); ok && call.Fun == child {
			return true
		}
		child = parent
	}
	return false
}

func exprListContainsNode(exprs []ast.Expr, node ast.Node) bool {
	for _, expr := range exprs {
		if expr == node {
			return true
		}
	}
	return false
}

func unparenExpr(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
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
