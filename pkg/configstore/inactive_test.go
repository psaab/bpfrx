package configstore

import (
	"strings"
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

// --- MAJOR 2: `show | display set` round-trips deactivate through the
// store. LoadSet / LoadMerge must apply a `deactivate <path>` line by
// marking the node inactive (not skip it, not parse a junk path), so an
// inactive node survives a serialize -> reload cycle instead of coming back
// active.

func enterCfg(t *testing.T, s *Store) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
}

// LoadSet of display-set output containing a `deactivate` line must restore
// the inactive node. Non-tautological: if LoadSet skipped the deactivate
// line (the pre-fix behavior) the node would reload active and the round-
// tripped display-set would lack the deactivate line.
func TestLoadSetRoundTripsDeactivate(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)

	displaySet := strings.Join([]string{
		"set system host-name keep",
		"set system name-server 9.9.9.9",
		"deactivate system name-server 9.9.9.9",
	}, "\n")

	if _, err := s.LoadSet(displaySet); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}

	out := s.ShowCandidateSet()
	if !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("LoadSet did not preserve the deactivate marker; ShowCandidateSet:\n%s", out)
	}
	// And no junk node literally named "deactivate" leaked in.
	if strings.Contains(out, "set deactivate ") {
		t.Fatalf("deactivate line parsed as a junk set path:\n%s", out)
	}
	// The active sibling survived.
	if !strings.Contains(out, "set system host-name keep") {
		t.Fatalf("active host-name lost on LoadSet:\n%s", out)
	}
}

// LoadMerge of hierarchical text with an `inactive:` block must serialize
// (FormatSet) to a deactivate line and merge back as inactive — the
// hierarchical -> FormatSet -> ParseSetVerb replay path inside LoadMerge.
func TestLoadMergeHierarchicalPreservesInactive(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)

	hier := `system {
    host-name keep;
    inactive: name-server 9.9.9.9;
}`
	if err := s.LoadMerge(hier); err != nil {
		t.Fatalf("LoadMerge: %v", err)
	}

	out := s.ShowCandidateSet()
	if !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("LoadMerge dropped the inactive marker; ShowCandidateSet:\n%s", out)
	}
}

// Full store-level display-set round trip: author inactive config, emit
// display-set, reload it into a fresh store via LoadSet, and re-emit. The
// deactivate line must be byte-stable across the cycle.
func TestDisplaySetRoundTripStable(t *testing.T) {
	s1 := newTestStore(t)
	enterCfg(t, s1)
	if err := s1.LoadMerge(`system {
    host-name keep;
    inactive: name-server 9.9.9.9;
}
security {
    policies {
        from-zone trust to-zone untrust {
            inactive: policy parked { then { deny; } }
            policy live { match { source-address any; destination-address any; application any; } then { permit; } }
        }
    }
}`); err != nil {
		t.Fatalf("seed LoadMerge: %v", err)
	}

	first := s1.ShowCandidateSet()

	s2 := newTestStore(t)
	enterCfg(t, s2)
	if _, err := s2.LoadSet(first); err != nil {
		t.Fatalf("reload LoadSet: %v", err)
	}
	second := s2.ShowCandidateSet()

	for _, want := range []string{
		"deactivate system name-server 9.9.9.9",
		"deactivate security policies from-zone trust to-zone untrust policy parked",
	} {
		if !strings.Contains(second, want) {
			t.Fatalf("reloaded display-set lost %q:\n%s", want, second)
		}
	}
	if first != second {
		t.Fatalf("display-set not stable across reload:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}
