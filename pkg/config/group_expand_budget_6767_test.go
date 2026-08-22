package config

import (
	"fmt"
	"strings"
	"testing"
)

// #6767: the apply-groups work budget charged ONE unit per `apply-groups <name>`
// reference resolved, and mergeNodes — which does the actual cloning and merging
// — took no budget at all.
//
// A wildcard group container is merged into EVERY matching destination
// container, so the real cost is the (wildcard node x matching container)
// product. A config with a handful of references could therefore build a
// quadratic AST while charging a handful of units, and the budget that exists
// to stop exactly that never fired.
//
// The fixtures below are built from `set` commands through ParseSetCommand +
// SetPath, never NewParser, because the parser treats newlines as whitespace and
// merges every line into one node.

func buildTree6767(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range lines {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// wildcardFanout6767 builds a config with ONE wildcard group applied once, whose
// expansion touches `containers` destination containers each receiving `depth`
// nodes. Pre-#6767 this charges 1 unit no matter how large it is.
func wildcardFanout6767(containers, leaves int) []string {
	var out []string
	// A group whose interface container is a wildcard: it merges into EVERY
	// interface below.
	for i := 0; i < leaves; i++ {
		out = append(out, fmt.Sprintf(
			"set groups WIDE interfaces <*> unit 0 family inet address 10.%d.%d.1/24", i/250, i%250))
	}
	for c := 0; c < containers; c++ {
		out = append(out, fmt.Sprintf("set interfaces ge-0/0/%d unit 0 family inet mtu 1500", c))
	}
	out = append(out, "set apply-groups WIDE")
	return out
}

// TestPathologicalWildcardFanoutIsRefused6767 is the defect proper.
//
// It drives the PUBLIC ExpandGroups so it depends on the behaviour, not on the
// internal budget plumbing. Pre-#6767 this expands happily: the single
// `apply-groups WIDE` reference charges ONE unit, mergeNodes charges nothing,
// and the quadratic AST is built unchecked.
func TestPathologicalWildcardFanoutIsRefused6767(t *testing.T) {
	// 400 x 400 = 160k merge units, comfortably past maxGroupExpandWork=100000,
	// while each individual list stays small enough to build quickly.
	tree := buildTree6767(t, wildcardFanout6767(400, 400))

	err := tree.ExpandGroups()
	if err == nil {
		t.Fatalf("a 400x400 wildcard fan-out expanded WITHOUT error. maxGroupExpandWork is "+
			"%d and the budget exists to refuse exactly this — but work was charged per "+
			"apply-groups REFERENCE (one, here) rather than per node merged, so a "+
			"generated or pathological config builds a quadratic AST unchecked",
			maxGroupExpandWork)
	}
	if !strings.Contains(err.Error(), "work budget") {
		t.Errorf("expansion failed for the wrong reason: %v", err)
	}
}

// TestOrdinaryConfigStillExpands6767 is the TIGHTENING control.
//
// Charging per merged node makes the budget bite sooner. A fix that charged too
// aggressively — or lowered the ceiling — would satisfy both tests above while
// refusing ordinary configs, which is a commit-blocking regression far worse
// than the quadratic AST. This pins that a realistic apply-groups config still
// expands, and that its expansion is CORRECT rather than merely error-free.
func TestOrdinaryConfigStillExpands6767(t *testing.T) {
	tree := buildTree6767(t, []string{
		"set groups COMMON interfaces <*> unit 0 family inet mtu 9000",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set apply-groups COMMON",
	})
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("an ordinary two-interface apply-groups config was REFUSED: %v — the "+
			"budget now bites on configs it must not", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig after expansion: %v", err)
	}
	for _, name := range []string{"ge-0/0/0", "ge-0/0/1"} {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil {
			t.Fatalf("%s did not compile", name)
		}
		var mtu int
		for _, u := range ifc.Units {
			if u != nil && u.MTU != 0 {
				mtu = u.MTU
			}
		}
		if mtu != 9000 {
			t.Errorf("%s unit MTU = %d, want 9000 from the wildcard group — the group "+
				"expanded without error but did not actually apply", name, mtu)
		}
	}
}

// deepGroupTree6767 builds a NON-wildcard group with `units` unit containers
// under one interface, applied into one matching container.
//
// Built directly rather than through ParseSetCommand: at the size needed to
// cross maxGroupExpandWork the set-command path spends minutes in SetPath, and
// the parser is not what is under test here.
func deepGroupTree6767(units int) *ConfigTree {
	// Shaped WIDE-ish but shallow-fanned on purpose: each unit carries many
	// leaves rather than there being many units. mergeNodes scans the whole
	// destination sibling list for each source container, so a fixture with
	// 100k SIBLINGS spends minutes in that O(n^2) scan before the budget trips
	// (measured: 185 s). Same node count, ~1/100th the siblings, same property
	// under test.
	const leavesPerUnit = 100
	unitCount := units/leavesPerUnit + 1
	groupUnits := make([]*Node, 0, unitCount)
	for i := 0; i < unitCount; i++ {
		leaves := make([]*Node, 0, leavesPerUnit)
		for j := 0; j < leavesPerUnit; j++ {
			leaves = append(leaves, &Node{
				Keys:   []string{fmt.Sprintf("address 10.%d.%d.1/24", j/250, j%250)},
				IsLeaf: true,
			})
		}
		groupUnits = append(groupUnits, &Node{
			Keys: []string{"unit", fmt.Sprint(i)},
			Children: []*Node{{
				Keys:     []string{"family", "inet"},
				Children: leaves,
			}},
		})
	}
	return &ConfigTree{Children: []*Node{
		{Keys: []string{"groups"}, Children: []*Node{
			{Keys: []string{"DEEP"}, Children: []*Node{
				{Keys: []string{"interfaces"}, Children: []*Node{
					{Keys: []string{"ge-0/0/0"}, Children: groupUnits},
				}},
			}},
		}},
		{Keys: []string{"interfaces"}, Children: []*Node{
			{Keys: []string{"ge-0/0/0"}, Children: []*Node{
				{Keys: []string{"unit", "0"}, Children: []*Node{
					{Keys: []string{"family", "inet"}, Children: []*Node{
						{Keys: []string{"mtu", "1500"}, IsLeaf: true},
					}},
				}},
			}},
		}},
		{Keys: []string{"apply-groups", "DEEP"}, IsLeaf: true},
	}}
}

// TestDeepNonWildcardGroupIsCharged6767 binds the per-merged-node charge.
//
// The wildcard fan-out test above passes with ONLY the clone charged, so
// removing the per-node charge is invisible to it. This shape has no wildcard
// and no fan-out — its whole cost is the size of the group subtree being merged
// — so it is refused only if each merged node is charged.
func TestDeepNonWildcardGroupIsCharged6767(t *testing.T) {
	tree := deepGroupTree6767(maxGroupExpandWork + 5000)

	err := tree.ExpandGroups()
	if err == nil {
		t.Fatalf("a group subtree with more than maxGroupExpandWork (%d) nodes merged "+
			"WITHOUT error. With no wildcard there is no fan-out to charge, so only the "+
			"per-merged-node charge can bound it — one unit per apply-groups reference "+
			"cannot", maxGroupExpandWork)
	}
	if !strings.Contains(err.Error(), "work budget") {
		t.Errorf("expansion failed for the wrong reason: %v", err)
	}
}

// TestRealisticConfigStillExpands6767 is the second TIGHTENING control, and it
// is sized to bite.
//
// The two-interface control below is far too small to notice an over-aggressive
// charge — charging 100x per node still fits inside maxGroupExpandWork there,
// so it passed a mutation that multiplied every charge by 100. A realistic
// chassis (48 ports, a group applying a handful of settings to each) is the
// smallest shape where over-charging actually refuses a config an operator
// would really write.
func TestRealisticConfigStillExpands6767(t *testing.T) {
	// Sized to BITE. A three-setting group over 48 ports costs a few hundred
	// units, so a mutation multiplying every charge by 100 still fits inside
	// maxGroupExpandWork and the control passes — measured. A realistic
	// standardised-port group carries far more than three settings; at ~30 the
	// 1x cost is ~1500 units, which a 100x over-charge pushes past the ceiling.
	var lines []string
	for i := 0; i < 30; i++ {
		lines = append(lines, fmt.Sprintf(
			"set groups CHASSIS interfaces <*> unit 0 family inet address 10.%d.%d.1/24",
			i/250, i%250))
	}
	for i := 0; i < 48; i++ {
		lines = append(lines, fmt.Sprintf(
			"set interfaces ge-0/0/%d unit 0 family inet address 10.0.%d.1/24", i, i))
	}
	lines = append(lines, "set apply-groups CHASSIS")

	tree := buildTree6767(t, lines)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("a realistic 48-port apply-groups config was REFUSED: %v — the budget now "+
			"bites on configs an operator would really write, which is a commit-blocking "+
			"regression worse than the quadratic AST it was meant to prevent", err)
	}
}
