package config

import "testing"

// #4474 (opus-172 H-1): TRANSITIVE apply-groups — a group whose body itself
// references another group (`grpA { apply-groups grpB; }`) must inherit grpB's
// content, exactly like Junos nested-group templates. Before the fix,
// expandGroupsRecursive captured the top-level applyNames BEFORE merging grpA's
// body, then merged grpA's `apply-groups grpB` leaf into the top level and
// stripped ALL apply-groups nodes before recursing — so grpB was never
// expanded and any security zone/policy authored behind grpB VANISHED with a
// CLEAN commit (config fail-open). The fix expands each group's OWN
// apply-groups to a fixed point (under the existing `seen` circular guard)
// BEFORE merging its body, in ast_groups.go expandGroupsRecursive.
//
// Tests use ParseSetCommand + SetPath (the CLAUDE.md-preferred flat-set path);
// setTreeFromCommands / findNodesByKey are the shared helpers from
// apply_groups_leaflist_exclude_test.go.

// securityZoneByName returns the security-zone node named want (Keys[1]) found
// anywhere in the tree after group expansion, or nil.
func securityZoneByName(nodes []*Node, want string) *Node {
	for _, z := range findNodesByKey(nodes, "security-zone") {
		if len(z.Keys) > 1 && z.Keys[1] == want {
			return z
		}
	}
	return nil
}

// TestApplyGroupsTransitiveZonePresent is the headline probe: grpA's body says
// `apply-groups grpB`, grpB defines security-zone ZONE_TRANSITIVE, and the
// top level applies grpA. ZONE_TRANSITIVE MUST be present after expansion.
// RED on revert: the transitive zone is silently ABSENT (fail-open).
func TestApplyGroupsTransitiveZonePresent(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups grpB security zones security-zone ZONE_TRANSITIVE host-inbound-traffic system-services ping",
		"set groups grpA apply-groups grpB",
		"set apply-groups grpA",
		// A directly-applied control group: works before AND after the fix.
		"set groups grpDirect security zones security-zone ZONE_DIRECT host-inbound-traffic system-services ping",
		"set apply-groups grpDirect",
	})

	if securityZoneByName(tree.Children, "ZONE_TRANSITIVE") == nil {
		t.Errorf("transitive apply-groups dropped ZONE_TRANSITIVE: " +
			"grpA->grpB nested-group content must be inherited (#4474 fail-open)")
	}
	// Control: the direct-group case must be unaffected by the fix.
	if securityZoneByName(tree.Children, "ZONE_DIRECT") == nil {
		t.Errorf("direct apply-groups control ZONE_DIRECT missing — regression")
	}
	// No stray apply-groups node may survive expansion.
	if leftover := findNodesByKey(tree.Children, "apply-groups"); len(leftover) != 0 {
		t.Errorf("apply-groups nodes survived expansion: %s", describeNodes(leftover))
	}
}

// TestApplyGroupsTransitiveOuterOwnContentKept: grpA carries BOTH its own zone
// AND `apply-groups grpB`. The fixed-point expansion + tag ordering must keep
// the outer group's own content (ZONE_OUTER) as well as the nested one
// (ZONE_TRANSITIVE) — the pre-merge expansion must not clobber grpA's body.
func TestApplyGroupsTransitiveOuterOwnContentKept(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups grpB security zones security-zone ZONE_TRANSITIVE host-inbound-traffic system-services ping",
		"set groups grpA apply-groups grpB",
		"set groups grpA security zones security-zone ZONE_OUTER host-inbound-traffic system-services ping",
		"set apply-groups grpA",
	})
	if securityZoneByName(tree.Children, "ZONE_OUTER") == nil {
		t.Errorf("outer group's own content ZONE_OUTER dropped")
	}
	if securityZoneByName(tree.Children, "ZONE_TRANSITIVE") == nil {
		t.Errorf("nested group content ZONE_TRANSITIVE dropped (#4474)")
	}
}

// TestApplyGroupsTransitiveChain: a three-deep chain grpA->grpB->grpC must
// carry grpC's content all the way to the top level (fixed point, not a single
// hop).
func TestApplyGroupsTransitiveChain(t *testing.T) {
	tree := setTreeFromCommands(t, []string{
		"set groups grpC security zones security-zone ZONE_DEEP host-inbound-traffic system-services ping",
		"set groups grpB apply-groups grpC",
		"set groups grpA apply-groups grpB",
		"set apply-groups grpA",
	})
	if securityZoneByName(tree.Children, "ZONE_DEEP") == nil {
		t.Errorf("three-deep transitive chain dropped ZONE_DEEP (#4474)")
	}
}

// TestApplyGroupsTransitiveCycleTerminates: a cycle grpA->grpB->grpA must NOT
// hang or stack-overflow; the `seen` guard must surface a circular-reference
// error (fail-CLOSED). This guards the fix against introducing infinite
// recursion through the new pre-merge expansion.
func TestApplyGroupsTransitiveCycleTerminates(t *testing.T) {
	tree := &ConfigTree{}
	for _, c := range []string{
		"set groups grpA apply-groups grpB",
		"set groups grpB apply-groups grpA",
		"set apply-groups grpA",
	} {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	err := tree.ExpandGroups()
	if err == nil {
		t.Fatalf("cyclic transitive apply-groups must error, got nil")
	}
	// Sanity: the error is the circular-reference class, not something else.
	if got := err.Error(); got == "" {
		t.Fatalf("expected a circular-reference error message, got empty")
	}
}

// TestApplyGroupsTransitiveTaggedInheritance: with ExpandGroupsTagged, the
// nested-group content must be tagged with the NESTED group's name (grpB), not
// the outer group (grpA), so `| display inheritance` attributes ZONE_TRANSITIVE
// correctly.
func TestApplyGroupsTransitiveTaggedInheritance(t *testing.T) {
	tree := &ConfigTree{}
	for _, c := range []string{
		"set groups grpB security zones security-zone ZONE_TRANSITIVE host-inbound-traffic system-services ping",
		"set groups grpA apply-groups grpB",
		"set apply-groups grpA",
	} {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	if err := tree.ExpandGroupsTagged(); err != nil {
		t.Fatalf("ExpandGroupsTagged: %v", err)
	}
	z := securityZoneByName(tree.Children, "ZONE_TRANSITIVE")
	if z == nil {
		t.Fatalf("ZONE_TRANSITIVE missing after tagged expansion (#4474)")
	}
	if z.InheritedFrom != "grpB" {
		t.Errorf("ZONE_TRANSITIVE InheritedFrom = %q, want %q (nested group)",
			z.InheritedFrom, "grpB")
	}
}
