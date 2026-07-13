package config

import (
	"testing"
)

// TestMemberIsNestedSetNilGuard5671 is the #5671 RED-on-revert proof.
//
// memberIsNestedSet lacked the `&& as != nil` guard that its sibling
// lookupApplicationSet carries (#5179). The tolerant-load / peer-sync path
// (#1960) can admit a present-but-nil application-set slot
// (ApplicationSets[name] == nil). Without the guard, memberIsNestedSet
// reported such a slot as a nested set ("is a set: true"), so expandAppSet
// routed the member to lookupApplicationSet, which correctly skips the nil and
// returns not-found — turning a resolvable leaf-application reference into a
// hard "application-set not found" expansion error.
//
// The scenario is not reachable through the parser (the set grammar cannot
// produce a nil map value), so — like the #5179 sibling test — the config is
// constructed directly to model the tolerant-load state. Neutralizing the
// guard (dropping `&& as != nil`) turns both assertions RED: the direct
// classification flips to true, and the end-to-end expansion errors instead of
// resolving the shadowing leaf.
func TestMemberIsNestedSetNilGuard5671(t *testing.T) {
	// A real leaf application named "shadow" AND a present-but-nil app-set slot
	// of the same name. The nil slot must NOT win the nested-set classification;
	// the member must resolve as the leaf application.
	newApps := func() *ApplicationsConfig {
		return &ApplicationsConfig{
			Applications: map[string]*Application{
				"shadow": {Name: "shadow", Protocol: "tcp", DestinationPort: "443"},
			},
			ApplicationSets: map[string]*ApplicationSet{
				"parent": {Name: "parent", Applications: []string{"shadow"}},
				"shadow": nil, // tolerant-loaded null slot
			},
		}
	}

	t.Run("classification: nil slot is not a nested set", func(t *testing.T) {
		apps := newApps()
		if memberIsNestedSet("shadow", apps) {
			t.Fatalf("memberIsNestedSet(nil-valued app-set slot shadowing a leaf) = true, " +
				"want false so the member resolves as the leaf application")
		}
	})

	t.Run("expansion: member resolves as leaf, not not-found", func(t *testing.T) {
		apps := newApps()
		got, err := ExpandApplicationSet("parent", apps)
		if err != nil {
			t.Fatalf("ExpandApplicationSet(parent) unexpected error: %v "+
				"(nil app-set slot must fall through to the shadowing leaf)", err)
		}
		if len(got) != 1 || got[0] != "shadow" {
			t.Fatalf("ExpandApplicationSet(parent) = %v, want [shadow]", got)
		}
	})

	// Sanity: a non-nil user-defined nested set still classifies as a nested set
	// (the guard must not over-reject genuine sets).
	t.Run("non-nil nested set still classifies as set", func(t *testing.T) {
		apps := &ApplicationsConfig{
			Applications: map[string]*Application{},
			ApplicationSets: map[string]*ApplicationSet{
				"real": {Name: "real", Applications: []string{}},
			},
		}
		if !memberIsNestedSet("real", apps) {
			t.Fatalf("memberIsNestedSet(non-nil user set) = false, want true")
		}
	})
}
