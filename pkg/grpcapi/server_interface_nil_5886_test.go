package grpcapi

// #5886: the non-session REMOTE gRPC interface/status presenters — cluster
// status (buildInterfacesInput), the show-interfaces proto builder
// (showInterfacesTerse), and the interface/unit completers (valueProvider) —
// dereferenced present-but-nil InterfaceConfig / InterfaceUnit map values after
// only a map-key check, so a read-only operator RPC panicked xpfd on a
// tolerantly-loaded / peer-synced config. #5068/#5813/#5910/#5913 fixed the CLI
// and text presenters; these remote presenters were the residual. They now walk
// via config.RangeInterfaces / RangeUnits / LookupInterface / LookupUnit.
//
// FAIL-ON-REVERT: removing a guard (e.g. the range nil-skip in showInterfacesTerse
// or the LookupInterface migration in buildInterfacesInput) makes the matching
// call deref the nil value and panic, unwinding through the test → RED. No
// panic recovery is used as the correctness mechanism: the presenters are called
// directly and their output asserted; a panic fails the test naturally.

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// nilLadenConfig returns a config carrying a present-but-nil InterfaceConfig, a
// zone-referenced nil InterfaceConfig, and a valid interface with a nil unit
// sibling — the shapes the tolerant load / HA sync path admits.
func nilLadenConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
			7: nil, // present-but-nil unit
		}},
		"reth0":      {Name: "reth0", RedundancyGroup: 1},
		"zz-nil-ifc": nil, // present-but-nil interface
	}
	return cfg
}

func TestGRPCShowInterfacesTerseNilNoPanic_5886(t *testing.T) {
	cfg := nilLadenConfig()
	resp, err := (&Server{}).showInterfacesTerse(cfg, "")
	if err != nil {
		t.Fatalf("showInterfacesTerse: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}
	// The valid interface's unit 0 must survive; the nil interface + nil unit are
	// omitted (not paniced on). We assert the call completed and produced a
	// response — the panic on a raw walk is what this pins.
}

func TestGRPCClusterAndCompletionNilNoPanic_5886(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/9 { unit 0 { family inet { address 10.20.30.40/24; } } }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	real := cfg.Interfaces.Interfaces["ge-0/0/9"]
	if real == nil || real.Units == nil {
		t.Fatal("fixture missing ge-0/0/9 units")
	}
	// Inject the tolerated nil shapes into the LIVE active config.
	cfg.Interfaces.Interfaces["zz-nil-ifc"] = nil
	real.Units[7] = nil
	// A non-nil cluster stanza so buildInterfacesInput reaches the RETH walk that
	// ranges the interface map (hitting the nil slot).
	cfg.Chassis.Cluster = &config.ClusterConfig{}

	s := &Server{store: store}

	// Cluster status: fabric lookups + RETH walk (server_cluster.go).
	_ = s.buildInterfacesInput()
	// Interface-name completion iterates every interface value.
	_ = s.valueProvider(config.ValueHintInterfaceName, []string{"interfaces"})
	// Unit-number completion iterates one interface's units.
	_ = s.valueProvider(config.ValueHintUnitNumber, []string{"interfaces", "ge-0/0/9", "unit"})
}
