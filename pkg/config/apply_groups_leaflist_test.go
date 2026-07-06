package config

import "testing"

// #4070: apply-groups inheritance is TYPED per Junos, discriminated by the
// statement KIND (setSchema `multi:true && children==nil` == leaf-list), NOT by
// AST shape. A leaf-list statement UNIONs the group's members with the inline
// members; a scalar leaf OVERRIDES (inline wins). A leaf-list can be expressed
// either as a COLLAPSED leaf ("name-server 1.1.1.1 2.2.2.2", one Node with the
// values in Keys[1:]) or as a BLOCK container ("name-server { 1.1.1.1; 2.2.2.2;
// }", one Node with Keys==["name-server"] and the values as child leaves).
//
// PR-A (#4325, merged) made the MIXED shape stop emitting a duplicate leaf AND
// container for one key. This is the VALUE half: every leaf-list now UNIONs
// regardless of shape (was: collapsed+collapsed OVERRODE, block+block UNIONED —
// a shape-dependent divergence from Junos). The union order is inline members
// first, then group members not already present, deduplicated — CONSISTENT with
// the block+block order the pre-#4070 code already produced.
//
// These tests assert (a) union across all four shape combinations, (b) exactly
// ONE node per key (the #4325 no-duplicate invariant still holds), (c) dedup,
// and (d) scalar override + multi-key sibling containers are unaffected.
//
// Block-shape leaf-lists require hierarchical syntax (flat `set` cannot produce
// a block container — repeated `set name-server X` yields separate single-value
// leaves, not a block), so the block-shape cases use NewParser on a single
// well-formed hierarchical string. The collapsed / flat-set cases use
// ParseSetCommand + SetPath (the CLAUDE.md-preferred flat-set test path).

// systemNameServerNodes returns the distinct "name-server" nodes under the
// top-level "system" node after group expansion.
func systemNameServerNodes(t *testing.T, tree *ConfigTree) []*Node {
	t.Helper()
	sys := tree.FindChild("system")
	if sys == nil {
		t.Fatal("no system node after expansion")
	}
	return sys.FindChildren("name-server")
}

// nameServerValues collects every member value carried by a single name-server
// node, across both AST shapes (Keys[1:] for collapsed, child leaves for block).
func nameServerValues(n *Node) []string {
	return firewallMatchValues(n)
}

// assertMembers fails unless got contains exactly the wanted members (order
// independent, no extras, no duplicates).
func assertMembers(t *testing.T, what string, got, want []string) {
	t.Helper()
	seen := map[string]int{}
	for _, v := range got {
		seen[v]++
	}
	for _, w := range want {
		if seen[w] == 0 {
			t.Errorf("%s: missing member %q; got %v", what, w, got)
		} else if seen[w] > 1 {
			t.Errorf("%s: member %q appears %d times (dedup failed); got %v",
				what, w, seen[w], got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s: got %d members %v, want %d %v",
			what, len(got), got, len(want), want)
	}
}

// TestApplyGroupsLeafListMixedBlockGroupCollapsedStanza is CASE-D: the group
// defines the leaf-list as a BLOCK container and the inheriting stanza as a
// COLLAPSED leaf. Result: ONE node, UNION of both member sets (inline 9.9.9.9
// first, then the group's 1.1.1.1/2.2.2.2).
func TestApplyGroupsLeafListMixedBlockGroupCollapsedStanza(t *testing.T) {
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
	assertMembers(t, "mixed block-group/collapsed-stanza union",
		nameServerValues(ns[0]), []string{"9.9.9.9", "1.1.1.1", "2.2.2.2"})
}

// TestApplyGroupsLeafListMixedCollapsedGroupBlockStanza is CASE-D reversed: the
// group defines the leaf-list as a COLLAPSED leaf and the inheriting stanza as
// a BLOCK container. Result: ONE node, UNION of both member sets.
func TestApplyGroupsLeafListMixedCollapsedGroupBlockStanza(t *testing.T) {
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
	// The surviving node keeps the stanza's block-container shape and gains the
	// group's value as an additional child.
	if ns[0].IsLeaf {
		t.Fatalf("surviving node should keep the stanza block-container shape, "+
			"got %s", describeNodes(ns))
	}
	assertMembers(t, "mixed collapsed-group/block-stanza union",
		nameServerValues(ns[0]), []string{"1.1.1.1", "2.2.2.2", "9.9.9.9"})
}

// TestApplyGroupsLeafListSameShapeBlockUnion is CASE-C: both group and stanza
// express the leaf-list as a BLOCK container. Union preserved (unchanged from
// the pre-#4070 block+block behavior).
func TestApplyGroupsLeafListSameShapeBlockUnion(t *testing.T) {
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
	assertMembers(t, "same-shape block+block union",
		nameServerValues(ns[0]), []string{"9.9.9.9", "1.1.1.1", "2.2.2.2"})
}

// TestApplyGroupsLeafListSameShapeCollapsedUnion is CASE-B: both group and
// stanza express the leaf-list as a COLLAPSED leaf. Before #4070 this OVERRODE
// (group suppressed, inline wins) — the shape-dependent divergence from Junos.
// It now UNIONs, consistent with block+block. This is the RED-on-revert
// assertion for the collapsed leaf-list case: reverting the fix restores
// override (only 9.9.9.9), dropping the group's members.
func TestApplyGroupsLeafListSameShapeCollapsedUnion(t *testing.T) {
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
	// Inline value first, then group additions — inline precedence + order.
	if got := ns[0]; !got.IsLeaf || len(got.Keys) < 2 || got.Keys[1] != "9.9.9.9" {
		t.Fatalf("collapsed union must keep the inline value 9.9.9.9 first, "+
			"got %s", describeNodes(ns))
	}
	assertMembers(t, "same-shape collapsed+collapsed union",
		nameServerValues(ns[0]), []string{"9.9.9.9", "1.1.1.1", "2.2.2.2"})
}

// TestApplyGroupsLeafListFlatSetUnion drives the collapsed-shape union through
// the flat-set path (ParseSetCommand + SetPath, the CLAUDE.md-preferred flat
// syntax test). Repeated flat `set ... name-server X` produce separate
// single-value leaves; only ONE survives inline, and the group's member is
// unioned in. Also asserts dedup: a value present in BOTH the group and inline
// appears exactly once.
func TestApplyGroupsLeafListFlatSetUnion(t *testing.T) {
	cmds := []string{
		"set groups g system name-server 1.1.1.1",
		"set groups g system name-server 9.9.9.9", // duplicate of an inline value
		"set apply-groups g",
		"set system name-server 9.9.9.9",
	}
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("ExpandGroups: %v", err)
	}
	ns := systemNameServerNodes(t, tree)
	if len(ns) != 1 {
		t.Fatalf("flat-set name-server union must yield ONE node, got %d: %s",
			len(ns), describeNodes(ns))
	}
	// 9.9.9.9 is in both the group and inline — dedup to a single occurrence.
	assertMembers(t, "flat-set name-server union+dedup",
		nameServerValues(ns[0]), []string{"9.9.9.9", "1.1.1.1"})
}

// TestApplyGroupsLeafListPolicyMatchApplicationUnion is the fable-164 L-8
// regression: an inline policy `match application junos-http` that inherits a
// group's `match application junos-https` must compile to a policy matching
// BOTH. Before #4070 the collapsed+collapsed override silently DROPPED
// junos-https, so a `then deny` no longer denied junos-https — a
// security-relevant divergence. This is the headline RED-on-revert.
func TestApplyGroupsLeafListPolicyMatchApplicationUnion(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set groups g security policies from-zone trust to-zone untrust policy p match application junos-https",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application junos-http",
		"set security policies from-zone trust to-zone untrust policy p then deny",
		"set apply-groups g",
	}
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pol := findZonePairPolicy(t, cfg, "trust", "untrust", "p")
	assertMembers(t, "policy match application union (L-8)",
		pol.Match.Applications, []string{"junos-http", "junos-https"})
}

// TestApplyGroupsLeafListPolicySourceAddressUnion covers the same union for the
// policy `match source-address` leaf-list (the address-narrowing angle of L-8).
func TestApplyGroupsLeafListPolicySourceAddressUnion(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust address-book address net-a 10.0.0.0/24",
		"set security zones security-zone trust address-book address net-b 10.0.1.0/24",
		"set security zones security-zone untrust",
		"set groups g security policies from-zone trust to-zone untrust policy p match source-address net-b",
		"set security policies from-zone trust to-zone untrust policy p match source-address net-a",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set apply-groups g",
	}
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pol := findZonePairPolicy(t, cfg, "trust", "untrust", "p")
	// The compiler normalizes zone address-book names to zone-qualified form;
	// the union is what matters — both the inline and group members survive.
	assertMembers(t, "policy match source-address union",
		pol.Match.SourceAddresses,
		[]string{"zone-local/trust/net-a", "zone-local/trust/net-b"})
}

// TestApplyGroupsLeafListScalarStillOverrides pins that a SCALAR leaf keeps the
// override behavior: an inline host-name wins over the group's. This guards the
// union change against over-reach onto scalars.
func TestApplyGroupsLeafListScalarStillOverrides(t *testing.T) {
	cmds := []string{
		"set groups g system host-name from-group",
		"set apply-groups g",
		"set system host-name explicit-name",
	}
	tree := &ConfigTree{}
	for _, c := range cmds {
		path, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.HostName != "explicit-name" {
		t.Errorf("scalar host-name must override to inline value, got %q",
			cfg.System.HostName)
	}
}

// findZonePairPolicy is shared with compiler_policy_then_deny_3141_test.go.

// TestApplyGroupsMultiKeyContainerSiblingsNotSuppressed guards the leaf-list
// classification against over-reach: a group's multi-key container
// (family inet6 { ... }, Keys==["family","inet6"]) must NOT be suppressed or
// unioned into a stanza's sibling multi-key container (family inet { ... }) that
// only shares Keys[0]=="family". Multi-key containers are real hierarchical
// nodes, never leaf-lists, so both must survive as distinct nodes.
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
	ifaces := tree.FindChild("interfaces")
	if ifaces == nil {
		t.Fatal("no interfaces node after expansion")
	}
	eth0 := ifaces.FindChild("eth0")
	if eth0 == nil {
		t.Fatal("no interfaces eth0 node after expansion")
	}
	unit := eth0.FindChild("unit")
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
