package config

import (
	"fmt"
	"testing"
)

// #6780: the compiler NEVER emits a present-but-nil interface, unit, or
// redundancy-group slot — on the strict path OR the tolerant one.
//
// Why this test exists. Roughly a dozen sites across the tree carry a comment
// of the form "the tolerant / HA-sync path may carry a nil entry
// (#3494/#5068)" and guard against it. That premise was never demonstrated;
// tracing it back, the chain is circular:
//
//	#5068 justifies itself by citing compiler_validate_warn_nil_3494_test.go
//	  ↓  …whose own header states "The strict compiler never emits these nils."
//	#3494 justifies itself by citing the #3474/#3476 "reachability premise"
//	  ↓  …whose write-up (docs/feature-gaps.md) says the class is
//	     "DEFENSIVE hardening, NOT a reachable-bug fix".
//
// No link in that chain demonstrates a mechanism, and every nil slot in the
// repository is injected synthetically by a test. The structural reason is
// that each container has exactly ONE write site, and each stores a
// freshly-allocated pointer:
//
//	Interfaces.Interfaces[name]  compiler_interfaces.go  (ifc  := &InterfaceConfig{…})
//	ifc.Units[n]                 compiler_interfaces.go  (unit := &InterfaceUnit{…})
//	Cluster.RedundancyGroups     compiler_system.go      (rg   := &RedundancyGroup{…})
//
// …and no path deserializes a *Config: persistence decodes the AST
// (*ConfigTree) and recompiles, HA config-sync ships config TEXT, and the one
// JSON-tagged *Config (the userspace dataplane Snapshot) is marshal-only.
//
// This test makes that invariant ENFORCED rather than believed. If a future
// change introduces a nil-emitting path — a new config ingress, a map copy, an
// early-insert-then-fill — this goes RED at the source, which is where the
// class can actually be fixed. It is deliberately NOT a guard at a consumer:
// distributing the belief is what produced the doubled dead guards in
// pkg/cli/cli_show_interfaces_terse.go (the same nil check twice, once tagged
// #5886 and once #5068).
//
// FAIL-ON-REVERT: make either compiler write site store a nil (e.g. drop the
// allocation and store a nil *InterfaceUnit for a quarantined unit) and the
// matching subtest goes RED naming the slot.

// countNilSlots returns the number of present-but-nil interface, unit, and
// redundancy-group slots in a compiled config.
func countNilSlots(cfg *Config) (nilIfc, nilUnit, nilRG int, detail []string) {
	if cfg == nil {
		return 0, 0, 0, nil
	}
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			nilIfc++
			detail = append(detail, fmt.Sprintf("interface %q is a nil slot", name))
			continue
		}
		for n, unit := range ifc.Units {
			if unit == nil {
				nilUnit++
				detail = append(detail, fmt.Sprintf("interface %q unit %d is a nil slot", name, n))
			}
		}
	}
	if cc := cfg.Chassis.Cluster; cc != nil {
		for i, rg := range cc.RedundancyGroups {
			if rg == nil {
				nilRG++
				detail = append(detail, fmt.Sprintf("redundancy-group index %d is a nil slot", i))
			}
		}
	}
	return nilIfc, nilUnit, nilRG, detail
}

// nilSlotCorpus is deliberately weighted toward inputs that STRESS the
// quarantine / fold / last-writer-wins branches, because those are the only
// places a partially-built entry could plausibly be left behind. A corpus of
// only well-formed configs would pass vacuously.
func nilSlotCorpus() map[string][]string {
	return map[string][]string{
		// The realistic HA shape both RETH ownership modes actually consume.
		"reth-cluster": {
			"set chassis cluster cluster-id 1",
			"set chassis cluster authentication-key test-cluster-psk-6780",
			"set chassis cluster reth-count 2",
			"set chassis cluster no-private-rg-election",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster redundancy-group 1 node 1 priority 100",
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
			"set interfaces reth0 vlan-tagging",
			"set interfaces reth0 unit 50 vlan-id 50 family inet address 172.16.50.8/24",
			"set interfaces reth0 unit 80 vlan-id 80 family inet address 172.16.80.8/24",
			"set interfaces reth1 redundant-ether-options redundancy-group 1",
			"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		},
		// Malformed unit id: the lenient path QUARANTINES it. The question this
		// case answers is whether the quarantine drops the unit or leaves a
		// present-but-nil slot behind.
		"quarantined-unit-id": {
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
			"set interfaces reth0 unit abc family inet address 10.0.61.1/24",
			"set interfaces reth0 unit 0 family inet address 10.0.62.1/24",
		},
		"negative-unit-id": {
			"set interfaces reth0 unit -1 family inet address 10.0.61.1/24",
		},
		"overflow-unit-id": {
			"set interfaces reth0 unit 99999999999999999999 family inet address 10.0.61.1/24",
		},
		// Repeated spellings exercise the last-writer-wins unit merge.
		"duplicate-unit": {
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
			"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
			"set interfaces reth0 unit 0 family inet address 10.0.61.2/24",
		},
		// An interface with no units, and a unit with no family — the shapes
		// most likely to leave a half-built entry.
		"interface-without-units": {
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
		},
		"unit-without-family": {
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
			"set interfaces reth0 unit 0",
		},
		// Non-numeric and canonically-duplicate RG ids exercise the #6543
		// fold-by-canonical-id path, the only place RedundancyGroups grows.
		"redundancy-group-non-numeric": {
			"set chassis cluster cluster-id 1",
			"set chassis cluster redundancy-group xyz node 0 priority 200",
			"set interfaces reth0 redundant-ether-options redundancy-group 1",
		},
		"redundancy-group-duplicate-canonical-ids": {
			"set chassis cluster cluster-id 1",
			"set chassis cluster redundancy-group 1 node 0 priority 200",
			"set chassis cluster redundancy-group 01 node 1 priority 100",
			"set chassis cluster redundancy-group 001 node 0 priority 150",
		},
	}
}

// compileForNilSlotScan runs one compile and converts a PANIC into a named test
// failure instead of taking the test binary down with a SIGSEGV stack.
//
// This is not cosmetic. When the invariant is broken, the compiler frequently
// cannot even finish compiling its own output: pkg/config's tail gates walk the
// interface tree they just built (runTailGates -> vrrpTrackConfigWarnings,
// compiler_interfaces.go) and dereference it raw. Measured by mutation:
// injecting a nil interface slot at the compiler write site panics INSIDE
// CompileConfigLenient, before any consumer ever sees the config.
//
// That closes the reachability question from the other end. A "tolerantly
// loaded config carrying a nil slot" could not survive the very compile that
// would have produced it — so the premise that such a config reaches a consumer
// is not merely undemonstrated, it is self-defeating. Recovering here keeps the
// failure attributable to THIS test and names the mode and corpus entry.
func compileForNilSlotScan(t *testing.T, mode string, fn func(*ConfigTree) (*Config, error), tree *ConfigTree) (cfg *Config, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s compile PANICKED: %v\n"+
				"The compiler emitted a config it cannot itself walk — pkg/config's "+
				"own tail gates dereference the interface tree raw. Fix the "+
				"compiler write site: a nil slot must never be stored.", mode, r)
			cfg, err = nil, nil
		}
	}()
	cfg, err = fn(tree)
	return cfg, err
}

func TestCompilerNeverEmitsNilConfigSlots(t *testing.T) {
	for name, lines := range nilSlotCorpus() {
		t.Run(name, func(t *testing.T) {
			tree := buildTree(t, lines)
			compiled := 0
			for _, mode := range []struct {
				name string
				fn   func(*ConfigTree) (*Config, error)
			}{
				{"strict", CompileConfig},
				{"lenient", CompileConfigLenient},
			} {
				cfg, err := compileForNilSlotScan(t, mode.name, mode.fn, tree)
				if err != nil || cfg == nil {
					// A rejected config emits nothing, so it cannot carry a nil
					// slot. The tolerant path must still compile (#1960
					// no-brick), which the count below asserts.
					continue
				}
				compiled++
				nilIfc, nilUnit, nilRG, detail := countNilSlots(cfg)
				if nilIfc+nilUnit+nilRG > 0 {
					t.Errorf("%s compile emitted present-but-nil slots "+
						"(interfaces=%d units=%d redundancy-groups=%d): %v\n"+
						"A consumer walking this config would nil-deref. Fix the "+
						"compiler write site, not the consumer.",
						mode.name, nilIfc, nilUnit, nilRG, detail)
				}
			}
			// Guard against a vacuous pass: if NEITHER path produced a config,
			// the corpus entry asserted nothing at all.
			if compiled == 0 {
				t.Fatalf("neither the strict nor the tolerant path compiled this "+
					"corpus entry, so the nil-slot assertion was vacuous "+
					"(lines=%v)", lines)
			}
		})
	}
}
