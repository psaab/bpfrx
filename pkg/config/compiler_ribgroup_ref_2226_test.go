package config

import (
	"strings"
	"testing"
)

// #2226: commit-time strict validation of a rib-group `import-rib <rib>`
// cross-reference. An import-rib naming a rib that resolves to no real
// routing table (a typo, a non-existent routing-instance, or unparseable
// garbage) compiled cleanly and then, at apply time, mapped to a bare
// table 0 — which differs from any routing-instance's (>= 100) source
// table — so the applier installed an `ip rule from all lookup
// <sourceTable> pref 33000` for a rib that does not exist: a silent
// mis-leak of the source table into the main lookup with no diagnostic.
//
// validateRibGroupImportRibReferencesStrict now hard-rejects the dangling
// reference at commit; the applier's resolveRibTable ok=false guard is the
// runtime backstop (tested in pkg/routing/rules_test.go).
//
// Each case is exercised in BOTH AST shapes (flat-set via ParseSetCommand
// + SetPath, hierarchical via NewParser), in both directions: an
// UNDEFINED import-rib is hard-rejected at commit (the fail-on-revert
// assertion — neuter the validator and the reject disappears), and a
// DEFINED import-rib commits cleanly with no false reject.

func TestRibGroupImportRibUndefinedRejectedFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances dmz-vr instance-type virtual-router",
		"set routing-instances dmz-vr interface-routes rib-group inet dmz-leak",
		"set routing-options rib-groups dmz-leak import-rib does-not-exist.inet.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for import-rib does-not-exist.inet.0, got nil")
	}
	if !strings.Contains(err.Error(), "undefined rib") ||
		!strings.Contains(err.Error(), "does-not-exist.inet.0") {
		t.Fatalf("error = %v, want it to name the undefined rib", err)
	}
}

// A bare garbage token (no ".inet" suffix at all) is also undefined.
func TestRibGroupImportRibGarbageRejected(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances dmz-vr instance-type virtual-router",
		"set routing-instances dmz-vr interface-routes rib-group inet dmz-leak",
		"set routing-options rib-groups dmz-leak import-rib garbage",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for import-rib garbage, got nil")
	}
	if !strings.Contains(err.Error(), "undefined rib") ||
		!strings.Contains(err.Error(), "garbage") {
		t.Fatalf("error = %v, want it to name the undefined rib", err)
	}
}

func TestRibGroupImportRibUndefinedRejectedHierarchical(t *testing.T) {
	input := `routing-instances {
    dmz-vr {
        instance-type virtual-router;
        interface-routes {
            rib-group inet dmz-leak;
        }
    }
}
routing-options {
    rib-groups {
        dmz-leak {
            import-rib does-not-exist.inet.0;
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for import-rib does-not-exist.inet.0, got nil")
	}
	if !strings.Contains(err.Error(), "undefined rib") {
		t.Fatalf("error = %v, want undefined-rib rejection", err)
	}
}

// A defined rib-group importing a defined instance's rib + the main table
// commits cleanly (no false reject).
func TestRibGroupImportRibDefinedCommitsFlatSet(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances tunnel-vr instance-type virtual-router",
		"set routing-instances dmz-vr instance-type virtual-router",
		"set routing-instances dmz-vr interface-routes rib-group inet dmz-leak",
		"set routing-options rib-groups dmz-leak import-rib dmz-vr.inet.0",
		"set routing-options rib-groups dmz-leak import-rib tunnel-vr.inet.0",
		"set routing-options rib-groups dmz-leak import-rib inet.0",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("defined import-ribs must commit cleanly, got: %v", err)
	}
	rg := cfg.RoutingOptions.RibGroups["dmz-leak"]
	if rg == nil {
		t.Fatal("rib-group dmz-leak missing from compiled config")
	}
	if len(rg.ImportRibs) != 3 {
		t.Fatalf("import-rib list = %v, want 3 entries", rg.ImportRibs)
	}
}

// inet6.0 and "<instance>.inet6.0" are valid main-table / VRF rib names.
func TestRibGroupImportRibInet6Commits(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances vpn-vr instance-type virtual-router",
		"set routing-instances vpn-vr interface-routes rib-group inet6 v6-leak",
		"set routing-options rib-groups v6-leak import-rib vpn-vr.inet6.0",
		"set routing-options rib-groups v6-leak import-rib inet6.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("inet6 import-ribs must commit cleanly, got: %v", err)
	}
}

// The strict reject is downgraded to a warning on the tolerant load /
// peer-sync path so an already-persisted config carrying the typo still
// boots (#1960 fail-closed-on-load class).
func TestRibGroupImportRibUndefinedLenientWarns(t *testing.T) {
	tree := buildTree(t, []string{
		"set routing-instances dmz-vr instance-type virtual-router",
		"set routing-instances dmz-vr interface-routes rib-group inet dmz-leak",
		"set routing-options rib-groups dmz-leak import-rib does-not-exist.inet.0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must boot through undefined import-rib, got: %v", err)
	}
	if !warningsContain(cfg.Warnings, "rib-group import-rib reference") {
		t.Fatalf("expected a downgraded import-rib-reference warning, got: %v", cfg.Warnings)
	}
}
