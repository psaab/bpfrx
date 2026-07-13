package config

import (
	"strings"
	"testing"
)

// TestNATPoolReferenceUndefinedRejected_5626 proves the #5626 fix: a source- or
// destination-NAT rule whose `then ... pool <name>` names a pool that is NOT
// defined under `security nat source/destination pool` is REJECTED at the
// strict commit path (CompileConfig) instead of being silently accepted with
// only a warn-only advisory and then failing the translation closed at runtime
// (the SNAT builder marks the rule unusable / the DNAT builder drops it, so
// matching traffic is silently left untranslated).
//
// FAIL-ON-REVERT: neutralizing the gate (dropping the
// validateNATPoolReferencesStrict call from runUniformGates, or reverting the
// gate to a no-op so a missing pool only warns) makes CompileConfig accept the
// dangling-pool config, so the reject assertions below fire RED. Both AST
// shapes (flat-set and hierarchical) are covered.
func TestNATPoolReferenceUndefinedRejected_5626(t *testing.T) {
	// --- Source NAT, flat-set AST ---
	t.Run("snat-flatset-undefined", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
			"set security nat source rule-set rs1 rule r1 then source-nat pool ghost-pool",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected CompileConfig to reject an SNAT rule naming an undefined pool")
		}
		if !strings.Contains(err.Error(), "ghost-pool") {
			t.Fatalf("error %q must name the undefined pool", err.Error())
		}
		if !strings.Contains(err.Error(), "source-nat") {
			t.Fatalf("error %q must identify the NAT kind", err.Error())
		}
	})

	// --- Source NAT, hierarchical AST (load merge / saved config) ---
	t.Run("snat-hierarchical-undefined", func(t *testing.T) {
		tree := hierTree(t, `security {
    nat {
        source {
            rule-set rs1 {
                from zone trust;
                to zone untrust;
                rule r1 {
                    match { source-address 10.0.0.0/24; }
                    then { source-nat { pool { ghost-pool; } } }
                }
            }
        }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected CompileConfig to reject a hierarchical SNAT undefined-pool reference")
		}
		if !strings.Contains(err.Error(), "ghost-pool") {
			t.Fatalf("error %q must name the undefined pool", err.Error())
		}
	})

	// --- Destination NAT, flat-set AST ---
	t.Run("dnat-flatset-undefined", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.10/32",
			"set security nat destination rule-set rs1 rule r1 then destination-nat pool ghost-pool",
		)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected CompileConfig to reject a DNAT rule naming an undefined pool")
		}
		if !strings.Contains(err.Error(), "ghost-pool") {
			t.Fatalf("error %q must name the undefined pool", err.Error())
		}
		if !strings.Contains(err.Error(), "destination-nat") {
			t.Fatalf("error %q must identify the NAT kind", err.Error())
		}
	})

	// --- Destination NAT, hierarchical AST ---
	t.Run("dnat-hierarchical-undefined", func(t *testing.T) {
		tree := hierTree(t, `security {
    nat {
        destination {
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.10/32; }
                    then { destination-nat { pool ghost-pool; } }
                }
            }
        }
    }
}`)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected CompileConfig to reject a hierarchical DNAT undefined-pool reference")
		}
		if !strings.Contains(err.Error(), "ghost-pool") {
			t.Fatalf("error %q must name the undefined pool", err.Error())
		}
	})
}

// TestNATPoolReferenceDefinedAccepted_5626 proves the happy path is
// undisturbed: a NAT rule whose `then ... pool` names a DEFINED pool compiles
// on the strict path and carries the pool reference through to the typed
// config. Covers both SNAT and DNAT, and both AST shapes.
func TestNATPoolReferenceDefinedAccepted_5626(t *testing.T) {
	t.Run("snat-flatset-defined", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set security nat source pool real-pool address 100.64.0.7/32",
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
			"set security nat source rule-set rs1 rule r1 then source-nat pool real-pool",
		)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("defined SNAT pool reference must compile, got %v", err)
		}
		if len(cfg.Security.NAT.Source) != 1 || len(cfg.Security.NAT.Source[0].Rules) != 1 {
			t.Fatalf("expected one SNAT rule-set with one rule, got %+v", cfg.Security.NAT.Source)
		}
		if got := cfg.Security.NAT.Source[0].Rules[0].Then.PoolName; got != "real-pool" {
			t.Errorf("SNAT Then.PoolName = %q, want real-pool", got)
		}
	})

	t.Run("dnat-hierarchical-defined", func(t *testing.T) {
		tree := hierTree(t, `security {
    nat {
        destination {
            pool real-pool { address 10.0.0.5/32; }
            rule-set rs1 {
                from zone untrust;
                rule r1 {
                    match { destination-address 203.0.113.10/32; }
                    then { destination-nat { pool real-pool; } }
                }
            }
        }
    }
}`)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("defined DNAT pool reference must compile, got %v", err)
		}
		if cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) != 1 {
			t.Fatalf("expected one DNAT rule-set, got %+v", cfg.Security.NAT.Destination)
		}
		if got := cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Then.PoolName; got != "real-pool" {
			t.Errorf("DNAT Then.PoolName = %q, want real-pool", got)
		}
	})
}

// TestNATPoolReferenceGate_LenientDowngrade_5626 proves the strict/tolerant
// split (#1960 no-brick): the pool-reference definedness gate hard-rejects on
// the strict commit path but downgrades to a warning on the tolerant load /
// peer-sync path (CompileConfigLenient), so an already-persisted or peer-synced
// config carrying a dangling pool reference still LOADS — the snapshot builders
// independently fail closed (SNAT marks the rule unusable, DNAT drops it), so a
// leniently-loaded config installs nothing rather than mis-translating.
func TestNATPoolReferenceGate_LenientDowngrade_5626(t *testing.T) {
	t.Run("snat", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set security nat source rule-set rs1 from zone trust",
			"set security nat source rule-set rs1 to zone untrust",
			"set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24",
			"set security nat source rule-set rs1 rule r1 then source-nat pool ghost-pool",
		)
		// Strict path rejects.
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("strict CompileConfig must reject the dangling SNAT pool reference")
		}
		// Tolerant path loads with a warning instead of failing.
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant load must NOT hard-fail on a dangling SNAT pool reference, got %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "nat pool reference") && strings.Contains(w, "ghost-pool") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("tolerant load must record a NAT pool-reference downgrade warning, got %v", cfg.Warnings)
		}
	})

	t.Run("dnat", func(t *testing.T) {
		tree := flatTreeFromSets(t,
			"set security nat destination rule-set rs1 from zone untrust",
			"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.10/32",
			"set security nat destination rule-set rs1 rule r1 then destination-nat pool ghost-pool",
		)
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("strict CompileConfig must reject the dangling DNAT pool reference")
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant load must NOT hard-fail on a dangling DNAT pool reference, got %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "nat pool reference") && strings.Contains(w, "ghost-pool") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("tolerant load must record a NAT pool-reference downgrade warning, got %v", cfg.Warnings)
		}
	})
}
