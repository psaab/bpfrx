package config_test

// #1979 Layer B — Tier 3: tcp-mss commit-time range validation.
//
// tcp-mss stays OPAQUE in setSchema by design (its MSS value can live in
// either the kind node's flat Keys[1] OR a hierarchical `mss` sub-child — a
// dual value-location the declarative SchemaValidate walker cannot express),
// so its accept/reject is validated by the compiler AST pre-walk
// validateTCPMSSRanges and asserted here through CompileConfig (strict) /
// CompileConfigLenient (boot/HA-safe). NOT through SchemaValidate.
//
// Per the dual-AST rule (CLAUDE.md): flat set-syntax via ParseSetCommand +
// tree.SetPath; hierarchical via NewParser().Parse().

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func mssFlatTree(t *testing.T, cmds ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func mssHierTree(t *testing.T, input string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

func mssAcceptStrict(t *testing.T, tree *config.ConfigTree) {
	t.Helper()
	if _, err := config.CompileConfig(tree); err != nil {
		t.Fatalf("expected strict ACCEPT, got: %v", err)
	}
}

func mssRejectStrict(t *testing.T, tree *config.ConfigTree) {
	t.Helper()
	_, err := config.CompileConfig(tree)
	if err == nil {
		t.Fatal("expected strict REJECT, got nil")
	}
	if !strings.Contains(err.Error(), "tcp-mss") || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("error should reference tcp-mss out-of-range: %v", err)
	}
}

// --- Flat shape (the issue headline: `tcp-mss gre-in 70000` typo) ---

func TestTCPMSSRange_FlatShape(t *testing.T) {
	// Valid flat values accepted.
	for _, kind := range []string{"ipsec-vpn", "gre-in", "gre-out", "all-tcp"} {
		mssAcceptStrict(t, mssFlatTree(t, "set security flow tcp-mss "+kind+" 1400"))
	}
	// all-tcp 1396 (docs/ha-cluster.conf value) accepted.
	mssAcceptStrict(t, mssFlatTree(t, "set security flow tcp-mss all-tcp 1396"))
	// Boundary: 65535 accepted, 65536 rejected.
	mssAcceptStrict(t, mssFlatTree(t, "set security flow tcp-mss gre-in 65535"))
	mssRejectStrict(t, mssFlatTree(t, "set security flow tcp-mss gre-in 65536"))

	// The headline typo: every kind out-of-range flat is rejected.
	for _, kind := range []string{"ipsec-vpn", "gre-in", "gre-out", "all-tcp"} {
		mssRejectStrict(t, mssFlatTree(t, "set security flow tcp-mss "+kind+" 70000"))
	}
}

// --- Hierarchical shape (`gre-in { mss <n>; }`) ---

func TestTCPMSSRange_HierarchicalShape(t *testing.T) {
	// Valid hierarchical accepted (matches TestTCPMSSHierarchical).
	mssAcceptStrict(t, mssHierTree(t, `security {
    flow { tcp-mss {
        ipsec-vpn { mss 1360; }
        gre-in { mss 1360; }
        gre-out { mss 1360; }
    } }
}`))
	// Out-of-range in the mss child rejected.
	mssRejectStrict(t, mssHierTree(t, `security {
    flow { tcp-mss { gre-in { mss 70000; } } }
}`))
}

// --- The precedence trap (Codex r1 #3): the compiler selects the mss child
// FIRST; a mixed shape must validate ONLY the selected value. ---

func TestTCPMSSRange_MixedShapePrecedence(t *testing.T) {
	// gre-in 70000 { mss 1360 }: compiler selects the child 1360 and DISCARDS
	// the flat 70000 -> must NOT false-reject (this is the converged-plan
	// acceptance requirement). Verify both that it compiles AND that the
	// compiled value is the selected 1360.
	tree := mssHierTree(t, `security {
    flow { tcp-mss { gre-in 70000 { mss 1360; } } }
}`)
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("mixed shape gre-in 70000 { mss 1360 } must NOT false-reject: %v", err)
	}
	if cfg.Security.Flow.TCPMSSGreIn != 1360 {
		t.Fatalf("compiler should select the mss child 1360, got %d", cfg.Security.Flow.TCPMSSGreIn)
	}

	// gre-in 1360 { mss 70000 }: compiler selects the child 70000 -> REJECT
	// (the selected value is out of range).
	mssRejectStrict(t, mssHierTree(t, `security {
    flow { tcp-mss { gre-in 1360 { mss 70000; } } }
}`))

	// gre-in 1400 (flat) + gre-in { mss 1360 } both pass independently.
	mssAcceptStrict(t, mssFlatTree(t, "set security flow tcp-mss gre-in 1400"))
	mssAcceptStrict(t, mssHierTree(t, `security {
    flow { tcp-mss { gre-in { mss 1360; } } }
}`))
}

// --- Strict vs lenient (boot/HA safety — MANDATORY per plan §6) ---

func TestTCPMSSRange_StrictVsLenient(t *testing.T) {
	// Flat out-of-range.
	flat := mssFlatTree(t, "set security flow tcp-mss gre-in 70000")
	if _, err := config.CompileConfig(flat); err == nil {
		t.Fatal("strict CompileConfig must REJECT tcp-mss gre-in 70000")
	}
	cfg, err := config.CompileConfigLenient(flat)
	if err != nil {
		t.Fatalf("lenient CompileConfigLenient must WARN-LOAD (not error) a legacy out-of-range MSS: %v", err)
	}
	foundWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "tcp-mss") {
			foundWarn = true
			break
		}
	}
	if !foundWarn {
		t.Fatalf("lenient load should emit a tcp-mss warning, got warnings: %v", cfg.Warnings)
	}
	// The lenient COMPILE retains the raw value (the compiler does not
	// coerce — Layer A coerces at the snapshot/wire boundary,
	// pkg/dataplane/userspace/flow.go coerceWireU16, NOT at compile time).
	// The point of the lenient path is that the node still BOOTS (no
	// hard-fail), with the dataplane safe via Layer A. So we assert only
	// that compile succeeded and warned — not that the value was changed.

	// Node-aware lenient sibling (Store.SyncApply path) also warn-loads.
	if _, err := config.CompileConfigForNodeLenient(flat, 0); err != nil {
		t.Fatalf("CompileConfigForNodeLenient must WARN-LOAD: %v", err)
	}

	// Hierarchical out-of-range: strict reject, lenient warn-load.
	hier := mssHierTree(t, `security {
    flow { tcp-mss { gre-in { mss 70000; } } }
}`)
	if _, err := config.CompileConfig(hier); err == nil {
		t.Fatal("strict CompileConfig must REJECT hierarchical out-of-range MSS")
	}
	if _, err := config.CompileConfigLenient(hier); err != nil {
		t.Fatalf("lenient must WARN-LOAD hierarchical out-of-range MSS: %v", err)
	}
}
