package configstore

import (
	"testing"
)

// --- MAJOR 1: schema/commit-check must strip inactive BEFORE expanding
// groups, so an `inactive: apply-groups <name>` never reaches group
// expansion (ast_groups.go collects apply-groups by name without checking
// Inactive). Before the fix, schemaValidateExpandedTreeForNode cloned the
// raw tree and expanded groups first, so an inactive apply-groups to a
// missing group failed commit-check as an undefined group.

// Anchor: an ACTIVE apply-groups to a missing group MUST fail commit-check.
// This proves the next test is non-tautological — removing only the
// `inactive:` marker flips the result from pass to fail.
func TestCheckTextActiveApplyGroupsMissingFails(t *testing.T) {
	conf := checkValidConfig + `
apply-groups missinggroup;
`
	if _, err := CheckText(conf, -1); err == nil {
		t.Fatal("active apply-groups to a missing group must fail commit-check")
	}
}

// An `inactive: apply-groups <missing>` must commit-check CLEAN: the marker
// deactivates the group reference, so expansion never tries (and never
// fails on) the undefined group. Fails without the strip-before-expand fix.
func TestCheckTextInactiveApplyGroupsMissingPasses(t *testing.T) {
	conf := checkValidConfig + `
inactive: apply-groups missinggroup;
`
	if _, err := CheckText(conf, -1); err != nil {
		t.Fatalf("inactive: apply-groups to a missing group must commit-check clean, got: %v", err)
	}
}

// An `inactive: apply-groups <defined>` must NOT inherit the group's typed
// content into the schema gate: the compiler will never apply it, so the
// schema/check path must agree. Here the group carries a typed-leaf value
// that the strict gate rejects when active; deactivating the apply-groups
// reference must suppress that inherited-content validation.
func TestCheckTextInactiveApplyGroupsSuppressesInheritedSchemaError(t *testing.T) {
	groupWithBadLeaf := `
groups {
    badg {
        class-of-service {
            schedulers {
                be {
                    transmit-rate asd;
                }
            }
        }
    }
}
`
	// Active reference inherits the bad transmit-rate -> commit-check fails.
	active := checkValidConfig + groupWithBadLeaf + `
apply-groups badg;
`
	if _, err := CheckText(active, -1); err == nil {
		t.Fatal("active apply-groups badg must fail (inherits transmit-rate asd)")
	}
	// Deactivated reference suppresses inheritance -> commit-check passes.
	inactive := checkValidConfig + groupWithBadLeaf + `
inactive: apply-groups badg;
`
	if _, err := CheckText(inactive, -1); err != nil {
		t.Fatalf("inactive: apply-groups badg must commit-check clean (group never applied), got: %v", err)
	}
}

// The same strip-before-expand must hold for the node-aware (cluster) path
// (nodeID >= 0), which uses ExpandGroupsWithVars.
func TestCheckTextInactiveApplyGroupsMissingPassesPerNode(t *testing.T) {
	conf := checkValidConfig + `
inactive: apply-groups missinggroup;
`
	for _, nodeID := range []int{0, 1} {
		if _, err := CheckText(conf, nodeID); err != nil {
			t.Fatalf("node %d: inactive: apply-groups missing must pass, got: %v", nodeID, err)
		}
	}
}
