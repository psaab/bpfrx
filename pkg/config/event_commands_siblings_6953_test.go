package config

import (
	"strings"
	"testing"
)

// #6953: `event-options policy <p> then change-configuration commands` can hold
// TWO SIBLING nodes, and a singular `FindChild("commands")` read only the first
// — silently discarding every command on the second.
//
// The read was fixed by 59be5ce4d ("read every value at the four remaining
// #2419 sites").
//
// WHAT THIS ADDS, STATED NARROWLY, because a mutation corrected my first claim.
// Reverting the read to the singular `FindChild` reds BOTH this test and the
// pre-existing `TestEventChangeConfigCommands6714RepeatedStatementsAllCompile`
// — so the read was NOT unbound, and any assertion that it was would be false.
// #6714 authors its siblings as a repeated statement in ONE hierarchical file
// (`commands "a"; commands "b";`), which the parser keeps as siblings, and both
// of them carry their value in the packed Keys tail.
//
// This test covers the other route to the same shape, which #6714 never
// exercises: a config PERSISTED in the packed spelling and then amended by a
// `set` line. That produces a MIXED pair — sibling #1 packed-tail, sibling #2
// child-valued — and it is the only fixture here in which `SetPath` runs
// against an already-populated tree. If `SetPath`'s merge behaviour changed so
// the overlay stopped appending a sibling (or started appending one where it
// used to merge), #6714 would not notice; the shape assertions below would.
//
// HOW THE FIXTURE IS BUILT, AND WHY IT MATTERS.
//
// The sibling shape is NOT producible by either input path alone. The
// hierarchical parser emits one node, and `SetPath` MERGES repeated flat-set
// statements into one node's children rather than appending a sibling. It
// arises only in the overlay: a config PERSISTED in the packed spelling, then
// amended with a `set` line.
//
// So the fixture must reproduce that combination exactly:
//
//   - the persisted half goes through `NewParser` — that is what reading a
//     stored config file does;
//   - the overlay half goes through `ParseSetCommand` + `tree.SetPath`, which
//     is what a `set` line does. Feeding the set line to `NewParser` instead
//     would merge it into the existing node, produce NO sibling, and the test
//     would pass against the singular read it exists to catch.
//
// Hand-constructing two sibling nodes would be worse still: it would prove the
// accumulator loops, while proving nothing about whether production can ever
// hand it that shape. The assertion below therefore checks the shape FORMED
// before checking what compiled from it.
func TestPersistedPackedCommandsPlusFlatSetOverlay_6953(t *testing.T) {
	const persisted = `event-options {
    policy p {
        then {
            change-configuration {
                commands "set system host-name foo";
            }
        }
    }
}`
	const overlay = `set event-options policy p then change-configuration commands "delete system host-name"`

	tree, errs := NewParser(persisted).Parse()
	if len(errs) > 0 {
		t.Fatalf("the persisted half must parse: %v", errs[0])
	}

	// CONTROL. The persisted command alone must already compile, or a later
	// assertion that "both are present" could be satisfied by a change that
	// broke the packed spelling and happened to keep the overlay.
	base, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile persisted: %v", err)
	}
	if len(base.EventOptions) != 1 ||
		len(base.EventOptions[0].ThenCommands) != 1 ||
		base.EventOptions[0].ThenCommands[0] != "set system host-name foo" {
		t.Fatalf("control failed: the PACKED spelling alone did not compile to its "+
			"one command, so this fixture cannot measure what the overlay adds. got %+v",
			base.EventOptions)
	}

	path, err := ParseSetCommand(overlay)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", overlay, err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}

	// NON-VACUITY, and it is the load-bearing check. If the overlay merged into
	// the existing node instead of appending a sibling, there is only one
	// `commands` node, a singular read would find everything, and the assertion
	// below would pass against the very defect this test exists for.
	cc := changeConfigurationNode6953(t, tree)
	sibs := cc.FindChildren("commands")
	if len(sibs) != 2 {
		t.Fatalf("expected TWO sibling `commands` nodes after the overlay, got %d.\n"+
			"Without siblings this fixture does not exercise #6953 at all: a "+
			"singular FindChild would read the single node and every assertion "+
			"below would pass. Node shapes: %s", len(sibs), describeNodes6953(sibs))
	}
	// The two spellings differ, and the accumulator must handle both: the
	// packed tail carries its value in Keys, the overlay in a child.
	if len(sibs[0].Keys) < 2 {
		t.Errorf("sibling #1 is not the PACKED spelling (value in Keys): Keys=%v", sibs[0].Keys)
	}
	if len(sibs[1].Children) != 1 {
		t.Errorf("sibling #2 is not the OVERLAY spelling (value in a child): %s",
			describeNodes6953(sibs[1:2]))
	}

	got, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile after overlay: %v", err)
	}
	if len(got.EventOptions) != 1 {
		t.Fatalf("event policies = %d, want 1", len(got.EventOptions))
	}
	cmds := got.EventOptions[0].ThenCommands
	want := []string{"set system host-name foo", "delete system host-name"}
	if len(cmds) != len(want) {
		t.Fatalf("ThenCommands = %v, want %v.\n\n"+
			"A singular `FindChild(\"commands\")` returns only the first sibling, so "+
			"the overlaid command is silently dropped. That is worse than a total "+
			"no-op: the operator watches the first command take effect and "+
			"reasonably concludes the batch ran (#6953).", cmds, want)
	}
	for i := range want {
		if cmds[i] != want[i] {
			t.Errorf("ThenCommands[%d] = %q, want %q (order is the authored order: "+
				"persisted first, overlay second)", i, cmds[i], want[i])
		}
	}
}

func changeConfigurationNode6953(t *testing.T, tree *ConfigTree) *Node {
	t.Helper()
	for _, eo := range tree.Children {
		if len(eo.Keys) == 0 || eo.Keys[0] != "event-options" {
			continue
		}
		for _, pol := range eo.FindChildren("policy") {
			for _, then := range pol.FindChildren("then") {
				for _, cc := range then.FindChildren("change-configuration") {
					return cc
				}
			}
		}
	}
	t.Fatal("no event-options/policy/then/change-configuration node — the fixture " +
		"does not have the shape this test is about")
	return nil
}

func describeNodes6953(nodes []*Node) string {
	var b strings.Builder
	for i, n := range nodes {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString("Keys=")
		b.WriteString(strings.Join(n.Keys, "|"))
		b.WriteString(" children=")
		for j, c := range n.Children {
			if j > 0 {
				b.WriteString(",")
			}
			b.WriteString(strings.Join(c.Keys, "|"))
		}
	}
	return b.String()
}
