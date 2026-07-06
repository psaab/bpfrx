package config

import "testing"

// #4070 PR-A: a leaf-list can be expressed either as a COLLAPSED leaf
// ("name-server 1.1.1.1 2.2.2.2", one Node with Keys[0]=="name-server" and
// the values in Keys[1:]) or as a BLOCK container
// ("name-server { 1.1.1.1; 2.2.2.2; }", one Node with Keys==["name-server"]
// and the values as child leaves). Before the fix, apply-groups inheritance
// only cross-recognized the SAME shape: a collapsed group leaf overrode a
// collapsed stanza leaf (leaf-vs-leaf), and a block group container merged
// into a block stanza container (container-vs-container). When the two
// shapes were MIXED for the same key, mergeNodes recognized neither branch
// and emitted BOTH a leaf AND a container for the same key — a duplicate
// node that is never correct.
//
// These tests assert the KEY invariant of PR-A: after group expansion a
// given Keys[0] leaf-list appears as EXACTLY ONE node, never a leaf AND a
// container. They intentionally do NOT pin the union-vs-override VALUE
// decision for same-shape leaf-lists (that is the deferred half of #4070) —
// they only lock the same-shape behavior as UNCHANGED and require the mixed
// shape to stop producing a duplicate.
//
// Block-shape leaf-lists require hierarchical syntax (flat `set` cannot
// produce a block container — repeated `set name-server X` yields separate
// single-value leaves, not a block), so these tests use NewParser on a
// single well-formed hierarchical string, the same pattern as
// TestApplyGroupsMergeDoesNotOverride / TestApplyGroupsHierarchical.

// countNameServers returns the number of distinct "name-server" nodes under
// the top-level "system" node after group expansion, plus a shape summary.
func systemNameServerNodes(t *testing.T, tree *ConfigTree) []*Node {
	t.Helper()
	sys := tree.FindChild("system")
	if sys == nil {
		t.Fatal("no system node after expansion")
	}
	return sys.FindChildren("name-server")
}

// TestApplyGroupsMixedShapeBlockGroupCollapsedStanza is CASE-D: the group
// defines the leaf-list as a BLOCK container and the inheriting stanza as a
// COLLAPSED leaf. Before the fix this produced TWO name-server nodes (a leaf
// AND a container). After the fix exactly one node survives.
func TestApplyGroupsMixedShapeBlockGroupCollapsedStanza(t *testing.T) {
	input := `
groups {
    g {
        system {
            name-server {
                1.1.1.1;
                2.2.2.2;
            }
        }
    }
}
apply-groups g;
system {
    name-server 9.9.9.9;
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	ns := systemNameServerNodes(t, tree)
	if len(ns) != 1 {
		t.Fatalf("mixed-shape (block group + collapsed stanza) must yield "+
			"exactly ONE name-server node, got %d: %s",
			len(ns), describeNodes(ns))
	}
	// The explicit stanza value wins (same precedence rule the code already
	// applies for a collapsed leaf that shadows a group value).
	if got := ns[0]; !got.IsLeaf || len(got.Keys) < 2 || got.Keys[1] != "9.9.9.9" {
		t.Fatalf("surviving node should be the explicit stanza leaf "+
			"name-server 9.9.9.9, got %s", describeNodes(ns))
	}
}

// TestApplyGroupsMixedShapeCollapsedGroupBlockStanza is CASE-D reversed: the
// group defines the leaf-list as a COLLAPSED leaf and the inheriting stanza
// as a BLOCK container. Before the fix this also produced TWO name-server
// nodes. After the fix exactly one node survives.
func TestApplyGroupsMixedShapeCollapsedGroupBlockStanza(t *testing.T) {
	input := `
groups {
    g {
        system {
            name-server 9.9.9.9;
        }
    }
}
apply-groups g;
system {
    name-server {
        1.1.1.1;
        2.2.2.2;
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	ns := systemNameServerNodes(t, tree)
	if len(ns) != 1 {
		t.Fatalf("mixed-shape (collapsed group + block stanza) must yield "+
			"exactly ONE name-server node, got %d: %s",
			len(ns), describeNodes(ns))
	}
	// The explicit stanza (block container) wins; the group's collapsed value
	// is suppressed, so the survivor is the container holding 1.1.1.1/2.2.2.2.
	if got := ns[0]; got.IsLeaf {
		t.Fatalf("surviving node should be the explicit stanza block "+
			"container, got %s", describeNodes(ns))
	}
}

// TestApplyGroupsSameShapeBlockUnionUnchanged is CASE-C: both group and
// stanza express the leaf-list as a BLOCK container. The existing behavior
// (union: all values present under one container) MUST be unchanged by the
// fix — the deferred union-vs-override VALUE decision is not touched here.
func TestApplyGroupsSameShapeBlockUnionUnchanged(t *testing.T) {
	input := `
groups {
    g {
        system {
            name-server {
                1.1.1.1;
                2.2.2.2;
            }
        }
    }
}
apply-groups g;
system {
    name-server {
        9.9.9.9;
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	ns := systemNameServerNodes(t, tree)
	if len(ns) != 1 {
		t.Fatalf("same-shape block+block must yield ONE name-server node, "+
			"got %d: %s", len(ns), describeNodes(ns))
	}
	if ns[0].IsLeaf {
		t.Fatalf("same-shape block+block survivor must be a container, got %s",
			describeNodes(ns))
	}
	// Union preserved: stanza's own value plus both group values.
	got := map[string]bool{}
	for _, c := range ns[0].Children {
		got[c.Keys[0]] = true
	}
	for _, want := range []string{"9.9.9.9", "1.1.1.1", "2.2.2.2"} {
		if !got[want] {
			t.Errorf("same-shape block+block union missing %q; children=%v",
				want, got)
		}
	}
}

// TestApplyGroupsSameShapeCollapsedOverrideUnchanged is CASE-B: both group
// and stanza express the leaf-list as a COLLAPSED leaf. The existing
// behavior (override: the explicit stanza value wins, group suppressed) MUST
// be unchanged by the fix.
func TestApplyGroupsSameShapeCollapsedOverrideUnchanged(t *testing.T) {
	input := `
groups {
    g {
        system {
            name-server [ 1.1.1.1 2.2.2.2 ];
        }
    }
}
apply-groups g;
system {
    name-server 9.9.9.9;
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	ns := systemNameServerNodes(t, tree)
	if len(ns) != 1 {
		t.Fatalf("same-shape collapsed+collapsed must yield ONE name-server "+
			"node, got %d: %s", len(ns), describeNodes(ns))
	}
	got := ns[0]
	if !got.IsLeaf || len(got.Keys) != 2 || got.Keys[1] != "9.9.9.9" {
		t.Fatalf("same-shape collapsed+collapsed must keep only the explicit "+
			"stanza value name-server 9.9.9.9, got %s", describeNodes(ns))
	}
}

// TestApplyGroupsMultiKeyContainerSiblingsNotSuppressed guards the fix's
// cross-shape match against over-reach: a group's multi-key container
// (family inet6 { ... }, Keys==["family","inet6"]) must NOT be suppressed by
// a stanza's sibling multi-key container (family inet { ... }) that only
// shares Keys[0]=="family". Multi-key containers are real hierarchical nodes,
// never leaf-lists, so both must survive as distinct nodes.
func TestApplyGroupsMultiKeyContainerSiblingsNotSuppressed(t *testing.T) {
	input := `
groups {
    g {
        interfaces {
            eth0 {
                unit 0 {
                    family inet6 {
                        address fc00::1/64;
                    }
                }
            }
        }
    }
}
apply-groups g;
interfaces {
    eth0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	unit := tree.FindChild("interfaces").FindChild("eth0").FindChild("unit")
	if unit == nil {
		t.Fatal("no interfaces eth0 unit 0 after expansion")
	}
	fams := unit.FindChildren("family")
	if len(fams) != 2 {
		t.Fatalf("multi-key sibling containers family inet + family inet6 "+
			"must both survive, got %d: %s", len(fams), describeNodes(fams))
	}
}

// describeNodes renders a compact shape/keys summary for assertion messages.
func describeNodes(nodes []*Node) string {
	out := ""
	for i, n := range nodes {
		if i > 0 {
			out += "; "
		}
		shape := "container"
		if n.IsLeaf {
			shape = "leaf"
		}
		out += shape + " " + n.KeyPath()
	}
	return out
}
