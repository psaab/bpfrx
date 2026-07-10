package config

import (
	"fmt"
	"strings"
	"testing"
)

// buildGroupChain5194 assembles a config with a nested apply-groups chain
// g0 -> g1 -> ... -> gN (each group's body says `apply-groups g(k+1)`; the
// deepest group carries a real leaf) plus a top-level `apply-groups g0` that
// kicks off the chain. It uses the flat-set ParseSetCommand + SetPath loop (the
// only correct way to build a multi-line tree).
func buildGroupChain5194(t *testing.T, depth int) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	apply := func(line string) {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	for k := 0; k < depth; k++ {
		apply(fmt.Sprintf("set groups g%d apply-groups g%d", k, k+1))
	}
	// Deepest group terminates the chain with a concrete leaf.
	apply(fmt.Sprintf("set groups g%d system host-name deep", depth))
	// Top-level reference starts the transitive expansion.
	apply("set apply-groups g0")
	return tree
}

// TestApplyGroupsDepthBudget_5194 is the #5194 A3-b2-F1 fail-on-revert guard: a
// deep ACYCLIC nested-group chain must be rejected by the depth budget before it
// recurses toward stack exhaustion on commit / HA config-sync. The `seen` cycle
// guard only rejects a self-reference and the #4474 memo only collapses a
// converging DAG — neither bounds a chain of DISTINCT groups.
//
// Fail-on-revert: remove the `depth > maxGroupExpandDepth` check (or stop
// threading depth) and this goes RED — a chain far past the cap expands with no
// error (and, unbounded, would eventually overflow the goroutine stack).
func TestApplyGroupsDepthBudget_5194(t *testing.T) {
	tree := buildGroupChain5194(t, maxGroupExpandDepth+40)
	err := tree.ExpandGroups()
	if err == nil {
		t.Fatal("ExpandGroups must reject a nested-group chain deeper than maxGroupExpandDepth")
	}
	if !strings.Contains(err.Error(), "depth") {
		t.Fatalf("depth-budget error must mention depth, got: %v", err)
	}
}

// TestApplyGroupsShallowChainStillExpands_5194 guards against a false rejection:
// a chain well within the cap must still expand fully and inherit the deepest
// group's leaf. This proves the budget sits above legitimate nesting.
func TestApplyGroupsShallowChainStillExpands_5194(t *testing.T) {
	tree := buildGroupChain5194(t, 4) // 4 levels, far under the cap
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups must accept a shallow nested-group chain: %v", err)
	}
	// The deepest group's `system host-name deep` must have been inherited to
	// the root via the transitive chain.
	if !treeHasHostName5194(tree, "deep") {
		t.Fatalf("shallow chain did not inherit the deepest group's host-name; tree=%s", tree.FormatSet())
	}
}

func treeHasHostName5194(tree *ConfigTree, want string) bool {
	return strings.Contains(tree.FormatSet(), "set system host-name "+want)
}
