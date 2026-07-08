package config

import (
	"strings"
	"testing"
)

// #4573 (ps-037-A3 B-001 / B-002): the `vrrp-group <id>` instance slot has no
// schema value validator (a documented deferral, schema_interfaces.go), and
// parseVRRPGroups stored any numeric id verbatim while the VRRP state machine
// truncates it onto the single VRID wire byte (uint8(vi.cfg.GroupID)). So a
// `vrrp-group 256` wrapped to the reserved VRID 0 (a strict RFC peer discards
// the advert → the VIP never masters → HA cold-boot blackhole) and 257 aliased
// VRID 1 onto another group. validateVRRPGroupIDStrict makes an out-of-range id
// an operator-visible commit error, mirroring the chassis redundancy-group id
// gate (validateChassisClusterStrict). B-002: the priority/hold-time flat-set
// and hierarchical parse used `_ =` Atoi, silently resetting Priority to 0 (RFC
// 5798 resignation) on a bad parse; the fix keeps the default/prior value.
//
// FAIL-ON-REVERT: drop the validateVRRPGroupIDStrict dispatch in
// compileExpanded (compiler_uniformgates.go) or the range check in the
// validator and the out-of-range subtests go green on the BAD config — exactly
// the wrong-VRID regression this test exists to catch. The in-range and
// lenient-path subtests pin that the gate does not over-reject and does not
// brick a persisted config.

// vrrpGroupSetLines returns the flat-set lines that define a single vrrp-group
// with the given id under reth0 unit 0 family inet.
func vrrpGroupSetLines(id string) []string {
	base := "set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group " + id
	return []string{
		base + " virtual-address 10.0.61.1/24",
		base + " priority 200",
	}
}

func TestVRRPGroupIDOutOfRangeFailsCommit(t *testing.T) {
	// 256 truncates uint8(256) == 0 (reserved VRID); 0 and -1 are below the
	// RFC 5798 valid range (1..255).
	for _, id := range []string{"256", "0", "-1", "300", "65536"} {
		t.Run("id="+id, func(t *testing.T) {
			tree := replaySetLines(t, vrrpGroupSetLines(id))
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("expected commit to reject vrrp-group %s (VRID is a "+
					"single wire byte, RFC 5798 range 1..255), got nil error", id)
			} else if !strings.Contains(err.Error(), "vrrp-group id "+id) ||
				!strings.Contains(err.Error(), "out of") {
				t.Fatalf("error %q does not name the out-of-range vrrp-group id %s",
					err.Error(), id)
			}

			// Tolerant path (load / peer-sync) must NOT brick — it downgrades
			// to a warning so an already-persisted config still boots (#1960).
			lcfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient compile must not reject an out-of-range "+
					"vrrp-group id (no-brick), got %v", lerr)
			}
			if !warningsContain(lcfg.Warnings, "vrrp-group id") {
				t.Fatalf("lenient compile should have warned about the "+
					"vrrp-group id; warnings=%v", lcfg.Warnings)
			}
		})
	}
}

func TestVRRPGroupIDInRangeCommits(t *testing.T) {
	// The boundaries: 1 and 255 both fit the VRID byte and must commit cleanly
	// with no rejection and no warning.
	for _, id := range []string{"1", "100", "255"} {
		t.Run("id="+id, func(t *testing.T) {
			tree := replaySetLines(t, vrrpGroupSetLines(id))
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("in-range vrrp-group %s must commit cleanly, got %v", id, err)
			}
			if warningsContain(cfg.Warnings, "vrrp-group id") {
				t.Fatalf("in-range vrrp-group %s should not warn; warnings=%v",
					id, cfg.Warnings)
			}
			vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
			if vg == nil {
				t.Fatalf("vrrp-group %s did not compile its VIP", id)
			}
		})
	}
}

// TestVRRPPriorityNonNumericKeepsDefault pins B-002: a non-numeric priority on
// the lenient compile path no longer silently resets Priority to 0 (RFC 5798
// resignation). The constructor default (100) survives the bad Atoi.
func TestVRRPPriorityNonNumericKeepsDefault(t *testing.T) {
	// Flat-set shape: `priority abc` packs "abc" onto the group's Keys run.
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 priority abc",
	})
	// Use the lenient path: strict commit would reject via the schema
	// ValidateInteger(1,255) leaf, but the lenient / HA-sync load reaches
	// parseVRRPGroups with the bad token.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24")
	if vg == nil {
		t.Fatal("vrrp-group did not compile its VIP")
	}
	// FAIL-ON-REVERT: with the `_ =` Atoi swallow the group resigns at
	// priority 0; the fix keeps the constructor default of 100.
	if vg.Priority != 100 {
		t.Fatalf("non-numeric priority should keep the default 100, got %d "+
			"(a swallowed Atoi would resign the group at 0)", vg.Priority)
	}
}
