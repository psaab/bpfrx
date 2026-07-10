package config

import (
	"strings"
	"testing"
)

// #5184: the structured `priority` spellings are gated at the schema layer by
// the leaf's ValidateInteger(1,255), but the PACKED hierarchical one-liner
// `vrrp-group 1 priority 256;` packs the priority onto the instance node's Keys,
// which the schema walker consumes as an unvalidated identity token
// (walkInstanceChildren). parseVRRPGroups stored the out-of-range value verbatim
// into the wide int VRRPGroup.Priority, and the VRRP state machine later
// truncates it onto the single wire byte (uint8(priority) in sendAdvert) — so a
// `priority 256` wrapped to the RFC 5798 resignation value 0 (the group
// advertises "I resign" on every beacon and never holds the VIP → HA blackhole)
// and 300 aliased to 44 (a silent demotion). validateVRRPGroupPriorityStrict
// makes an out-of-range priority an operator-visible commit error on the
// compiled *Config — where the wide int still shows 256 as 256, before the
// uint8 narrowing — mirroring the vrrp-group id gate (validateVRRPGroupIDStrict,
// #4573).
//
// FAIL-ON-REVERT: drop the validateVRRPGroupPriorityStrict dispatch in
// compileExpanded (compiler_uniformgates.go) or the range check in the validator
// and the out-of-range subtests go green on the BAD config — exactly the
// resigning-instance regression this test exists to catch. The in-range and
// lenient-path subtests pin that the gate does not over-reject and does not
// brick a persisted config.

// vrrpGroupPrioritySetLines returns the flat-set lines that define a single
// vrrp-group under reth0 unit 0 family inet with the given priority.
func vrrpGroupPrioritySetLines(priority string) []string {
	base := "set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1"
	return []string{
		base + " virtual-address 10.0.61.1/24",
		base + " priority " + priority,
	}
}

// packedVrrpPriorityTree parses the hierarchical PACKED one-liner
// `vrrp-group 1 priority <p>;` (the spelling that bypasses the schema
// ValidateInteger(1,255)), returning the AST the compiler consumes.
func packedVrrpPriorityTree(t *testing.T, priority string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(`interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.1/24;
                    }
                    vrrp-group 1 priority ` + priority + `;
                }
            }
        }
    }
}`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	return tree
}

func TestVRRPGroupPriorityOutOfRangeFailsCommit(t *testing.T) {
	// 256 truncates uint8(256) == 0 (the RFC 5798 resignation value); 300
	// aliases to 44; 0 and -1 are below the valid range (1..255). Both the
	// packed hierarchical one-liner and the structured flat-set must reject.
	for _, priority := range []string{"256", "300", "0", "-1", "65536"} {
		t.Run("structured/priority="+priority, func(t *testing.T) {
			tree := replaySetLines(t, vrrpGroupPrioritySetLines(priority))
			assertPriorityRejected(t, tree, priority)
		})
		t.Run("packed/priority="+priority, func(t *testing.T) {
			tree := packedVrrpPriorityTree(t, priority)
			assertPriorityRejected(t, tree, priority)
		})
	}
}

// assertPriorityRejected pins that strict commit rejects the out-of-range
// priority (naming it) while the tolerant load / peer-sync path warns and boots.
func assertPriorityRejected(t *testing.T, tree *ConfigTree, priority string) {
	t.Helper()
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to reject vrrp-group priority %s (priority is "+
			"a single wire byte, RFC 5798 range 1..255), got nil error", priority)
	} else if !strings.Contains(err.Error(), "priority "+priority) ||
		!strings.Contains(err.Error(), "out of range") {
		t.Fatalf("error %q does not name the out-of-range priority %s",
			err.Error(), priority)
	}

	// Tolerant path (load / peer-sync) must NOT brick — it downgrades to a
	// warning so an already-persisted config still boots (#1960 no-brick).
	lcfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile must not reject an out-of-range vrrp-group "+
			"priority (no-brick), got %v", lerr)
	}
	if !warningsContain(lcfg.Warnings, "vrrp-group priority") {
		t.Fatalf("lenient compile should have warned about the vrrp-group "+
			"priority; warnings=%v", lcfg.Warnings)
	}
}

func TestVRRPGroupPriorityInRangeCommits(t *testing.T) {
	// The boundaries: 1 and 255 both fit the priority byte, plus the common
	// weights, must commit cleanly with no rejection and no warning.
	for _, priority := range []string{"1", "100", "200", "255"} {
		t.Run("structured/priority="+priority, func(t *testing.T) {
			tree := replaySetLines(t, vrrpGroupPrioritySetLines(priority))
			assertPriorityAccepted(t, tree, priority)
		})
		t.Run("packed/priority="+priority, func(t *testing.T) {
			tree := packedVrrpPriorityTree(t, priority)
			assertPriorityAccepted(t, tree, priority)
		})
	}
}

func assertPriorityAccepted(t *testing.T, tree *ConfigTree, priority string) {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("in-range vrrp-group priority %s must commit cleanly, got %v",
			priority, err)
	}
	if warningsContain(cfg.Warnings, "vrrp-group priority") {
		t.Fatalf("in-range vrrp-group priority %s should not warn; warnings=%v",
			priority, cfg.Warnings)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
	if vg == nil {
		t.Fatalf("vrrp-group priority %s did not compile its VIP", priority)
	}
	if strings.TrimSpace(priority) != "" {
		// The compiled Priority must equal the authored value (not the
		// constructor default) so we know the value flowed through the gate.
		wantByPriority := map[string]int{"1": 1, "100": 100, "200": 200, "255": 255}
		if want, ok := wantByPriority[priority]; ok && vg.Priority != want {
			t.Fatalf("compiled priority = %d, want %d", vg.Priority, want)
		}
	}
}
