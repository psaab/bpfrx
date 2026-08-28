package config

import (
	"strings"
	"testing"
)

// compiler_nat_then_occurrences_7013_test.go — #7013.
//
// A rule that authors the SAME mode twice loses one of them before anything
// validates it: NATThen's `PoolName` is a scalar, so
// `then destination-nat pool PD pool PD2` resolves to one pool and
// validateNATTerminalActionCardinalityStrict — which counts MODES — sees n == 1
// and does not fire. The config commits under STRICT with an operator-authored
// action discarded and no diagnostic.
//
// THE FIXTURES ASSERT REJECTION, NOT WHICH POOL SURVIVES. Measured at this head
// the FIRST authored value is the one that takes effect, in both spellings that
// carry two occurrences into the tree — but a fixture built on the survivor reds
// against a correct compiler and a buggy one alike, for opposite reasons, and
// the instinct on seeing that red is to "fix" the assertion. Rejection is the
// acceptance criterion and is invariant to it.
//
// THE BOUNDARY CASES ARE AS LOAD-BEARING AS THE REJECTIONS, because every one of
// them is a config the gate could plausibly be "completed" into rejecting, and
// two of them were rejected by the first version of this change:
//
//   - two separate `set ... pool X` lines — the second REPLACES the leaf, so
//     only one pool reaches the compiler and `show configuration` displays what
//     will be enforced. The issue body called this a collapse; it is ordinary
//     single-value-leaf behaviour at a different layer.
//   - duplicate `then` CONTAINERS — #3850 last-wins, already legal.
//     TestNATTerminalActionDupIdentical3850_5628 caught the summing version of
//     this change; the scope is now one container.
//   - `pool { P; persistent-nat { ... } }` — one authored pool with a
//     sub-stanza, not two. dual_ast_differential_test.go caught the version
//     that read the name from Keys only.

func natDupPoolSet7013(thenLines ...string) []string {
	return append([]string{
		"set security zones security-zone untrust",
		"set security nat destination pool PD address 10.0.0.5",
		"set security nat destination pool PD2 address 10.0.0.6",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.10",
	}, thenLines...)
}

// TestRepeatedSameModePoolRejected_7013 is the acceptance criterion, in both
// spellings and both orders.
//
// Both orders matter for the reason above: an implementation that counted only
// the DISCARDED occurrence rather than the authored ones would pass one order
// and fail the other, and a single-order fixture could not tell.
func TestRepeatedSameModePoolRejected_7013(t *testing.T) {
	for _, tc := range []struct {
		name  string
		then  []string
		pools [2]string
	}{
		{
			name:  "packed_run_PD_then_PD2",
			then:  []string{"set security nat destination rule-set rs1 rule r1 then destination-nat pool PD pool PD2"},
			pools: [2]string{"PD", "PD2"},
		},
		{
			name:  "packed_run_PD2_then_PD",
			then:  []string{"set security nat destination rule-set rs1 rule r1 then destination-nat pool PD2 pool PD"},
			pools: [2]string{"PD2", "PD"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, natDupPoolSet7013(tc.then...))
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatal("a rule authoring TWO destination-nat pools committed under strict. " +
					"One of them is silently discarded before validation runs — NATThen's " +
					"PoolName is a scalar — so the firewall translates differently from the " +
					"configuration as written, with no diagnostic (#7013)")
			}
			msg := err.Error()
			// The acceptance criterion names BOTH authored pools: a message that
			// named only the survivor would tell the operator the opposite of
			// what happened — that the pool they can see is the problem.
			for _, p := range tc.pools {
				if !strings.Contains(msg, p) {
					t.Fatalf("the rejection does not name authored pool %q: %q. The operator "+
						"has to be told WHICH pool was discarded, and the survivor alone does "+
						"not say that", p, msg)
				}
			}
			if !strings.Contains(msg, "pool") {
				t.Fatalf("the rejection does not name the repeated MODE: %q", msg)
			}
		})
	}
}

// TestSingleActionStillCompiles_7013 is the negative control, and without it
// every case above is satisfied by a gate that rejects all NAT.
func TestSingleActionStillCompiles_7013(t *testing.T) {
	for _, tc := range []struct{ name, then string }{
		{"one_pool_packed", "set security nat destination rule-set rs1 rule r1 then destination-nat pool PD"},
		{"one_off", "set security nat destination rule-set rs1 rule r1 then destination-nat off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, natDupPoolSet7013(tc.then))
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("a rule authoring ONE action must still commit, got: %v.\n"+
					"The occurrence gate must reject a REPEAT, not a mode — rejecting the "+
					"single case would make the cases above pass for the wrong reason", err)
			}
		})
	}
}

// TestSourceNatRepeatedModeRejected_7013 covers the other kind. The gate runs
// over both, and the occurrence record is populated at two separate lowering
// sites, so a fix applied to one is a fix applied to half the defect.
func TestSourceNatRepeatedModeRejected_7013(t *testing.T) {
	lines := []string{
		"set security zones security-zone untrust",
		"set security nat source pool PS address 10.0.0.5",
		"set security nat source pool PS2 address 10.0.0.6",
		"set security nat source rule-set rs1 from zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address 10.0.1.0/24",
		"set security nat source rule-set rs1 rule r1 then source-nat pool PS pool PS2",
	}
	tree := buildTree(t, lines)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a source-nat rule authoring TWO pools committed under strict. The " +
			"occurrence record is populated at the source and destination lowering sites " +
			"separately, so a gate wired to only one covers half the defect (#7013)")
	}
	for _, p := range []string{"PS", "PS2"} {
		if !strings.Contains(err.Error(), p) {
			t.Fatalf("the source-nat rejection does not name authored pool %q: %q", p, err)
		}
	}
}

// TestOccurrenceCounterSeesEveryShape_7013 pins the walk directly.
//
// The gate is only as complete as the shapes the counter reads, and a spelling
// it misses is a spelling that still commits silently. Driving the counter
// rather than the compiler is what makes an uncounted shape fail HERE, by name,
// instead of surfacing as one accepted case in the table above.
func TestOccurrenceCounterSeesEveryShape_7013(t *testing.T) {
	for _, tc := range []struct {
		name      string
		node      *Node
		wantPools int
	}{
		{
			name:      "packed_onto_the_then_node",
			node:      &Node{Keys: []string{"then", "destination-nat", "pool", "PD", "pool", "PD2"}},
			wantPools: 2,
		},
		{
			name: "packed_onto_the_kind_child",
			node: &Node{Keys: []string{"then"}, Children: []*Node{
				{Keys: []string{"destination-nat", "pool", "PD", "pool", "PD2"}},
			}},
			wantPools: 2,
		},
		{
			name: "hierarchical_children",
			node: &Node{Keys: []string{"then"}, Children: []*Node{
				{Keys: []string{"destination-nat"}, Children: []*Node{
					{Keys: []string{"pool", "PD"}},
					{Keys: []string{"pool", "PD2"}},
				}},
			}},
			wantPools: 2,
		},
		{
			// The name below the `pool` node — the shape the hierarchical
			// fixtures in dual_ast_differential_test.go use. A counter that read
			// Keys only saw ZERO pools here, which is what made the same config
			// record differently depending on how it was spelled.
			name: "pool_name_as_child",
			node: &Node{Keys: []string{"then"}, Children: []*Node{
				{Keys: []string{"destination-nat"}, Children: []*Node{
					{Keys: []string{"pool"}, Children: []*Node{{Keys: []string{"PD"}}}},
				}},
			}},
			wantPools: 1,
		},
		{
			// The flat-set path for `then source-nat pool PS pool PS2` builds the
			// repeat as a CHILD of the first pool node, not a sibling: the second
			// `pool` token opens a further path instead of extending the leaf. A
			// walk that reads siblings only sees one pool here and the packed
			// source-nat spelling commits silently.
			name: "nested_pool_repeat",
			node: &Node{Keys: []string{"then"}, Children: []*Node{
				{Keys: []string{"destination-nat"}, Children: []*Node{
					{Keys: []string{"pool", "PD"}, Children: []*Node{
						{Keys: []string{"pool", "PD2"}},
					}},
				}},
			}},
			wantPools: 2,
		},
		{
			// Junos nests `persistent-nat` under `pool`. Counting every child as
			// a pool name makes this read as two authored pools and rejects a
			// valid config; the compiler takes the FIRST child (nodeVal), so
			// this must too.
			name: "pool_with_persistent_nat_substanza_is_one_pool",
			node: &Node{Keys: []string{"then"}, Children: []*Node{
				{Keys: []string{"source-nat"}, Children: []*Node{
					{Keys: []string{"pool"}, Children: []*Node{
						{Keys: []string{"PS"}},
						{Keys: []string{"persistent-nat"}, Children: []*Node{{Keys: []string{"permit", "any-remote-host"}}}},
					}},
				}},
			}},
			wantPools: 1,
		},
		{
			// A DIFFERENT kind's actions must not be counted, or a rule with one
			// source-nat pool and one destination-nat pool reads as a duplicate.
			name: "other_kind_is_not_counted",
			node: &Node{Keys: []string{"then"}, Children: []*Node{
				{Keys: []string{"destination-nat", "pool", "PD"}},
				{Keys: []string{"source-nat", "pool", "PS"}},
			}},
			wantPools: 1,
		},
		{
			// A trailing bare `pool` is malformed, not a second authored pool;
			// counting it would report a duplicate for a syntax error.
			name:      "trailing_bare_pool_is_not_an_occurrence",
			node:      &Node{Keys: []string{"then", "destination-nat", "pool", "PD", "pool"}},
			wantPools: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind := "destination-nat"
			if len(tc.node.Children) > 0 && tc.node.Children[0].Name() == "source-nat" {
				kind = "source-nat"
			}
			got := natThenAuthoredOccurrences(tc.node, kind)
			if len(got.Pools) != tc.wantPools {
				t.Fatalf("counted %d authored pools %v, want %d — a shape the counter cannot "+
					"see is a spelling that still commits silently (#7013)",
					len(got.Pools), got.Pools, tc.wantPools)
			}
		})
	}
}

// TestHierarchicalRepeatedPoolRejected_7013 is the spelling #7013's acceptance
// criterion names literally — `destination-nat { pool PD; pool PD2; }` — and it
// reaches the compiler by a different route from the packed cases above: the
// real parser, not ParseSetCommand, and two sibling children rather than one
// token run. A counter wired only to packed runs passes every case above and
// still lets this commit.
func TestHierarchicalRepeatedPoolRejected_7013(t *testing.T) {
	txt := `security {
  zones { security-zone untrust; }
  nat {
    destination {
      pool PD { address 10.0.0.5; }
      pool PD2 { address 10.0.0.6; }
      rule-set rs1 {
        from zone untrust;
        rule r1 {
          match { destination-address 203.0.113.10; }
          then { destination-nat { pool PD; pool PD2; } }
        }
      }
    }
  }
}`
	tree, perr := NewParser(txt).Parse()
	if len(perr) != 0 {
		t.Fatalf("fixture did not parse: %v", perr)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("`then { destination-nat { pool PD; pool PD2; } }` committed under strict. " +
			"Both pools are in the tree and only the first reaches the dataplane, so the " +
			"config as displayed is not the config as enforced (#7013)")
	}
	for _, p := range []string{"PD", "PD2"} {
		if !strings.Contains(err.Error(), p) {
			t.Fatalf("the rejection does not name authored pool %q: %q", p, err)
		}
	}
}

// TestSeparateSetLinesReplaceAndCommit_7013 pins the boundary: this spelling is
// NOT the defect and must keep committing.
//
// It is the cell that stops the gate from being "completed" into rejecting a
// legal edit, and it also records the measurement that corrects the issue body —
// the tree after both lines holds ONE pool, so there is no discarded action for
// a commit gate to report.
func TestSeparateSetLinesReplaceAndCommit_7013(t *testing.T) {
	tree := buildTree(t, natDupPoolSet7013(
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool PD",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool PD2",
	))

	// The tree itself carries one pool: the discard happened at `set`, visibly,
	// not at commit, silently. Asserting the TREE and not just the compile
	// result is what makes this cell say WHY the spelling is legal — a later
	// change that started carrying both occurrences forward would flip this,
	// and the rejection below it would then be correct rather than a break.
	authored := natThenAuthoredOccurrences(natThenNode7013(t, tree), "destination-nat")
	if len(authored.Pools) != 1 {
		t.Fatalf("the candidate tree carries %d pools %v after two `set` lines; expected the "+
			"second to REPLACE the first. If the tree now carries both, this spelling has "+
			"become the #7013 defect and belongs with the rejections above", len(authored.Pools), authored.Pools)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("re-`set`ting a pool must commit — it is how an operator edits one — got: %v", err)
	}
	got := cfg.Security.NAT.Destination.RuleSets[0].Rules[0].Then.PoolName
	if got != "PD2" {
		t.Fatalf("the surviving pool is %q, want the re-`set` value PD2: a second `set` on a "+
			"single-value leaf replaces it, and `show configuration` shows PD2", got)
	}
}

// natThenNode7013 digs out rule r1's `then` node so a case can assert on the
// tree the compiler will read rather than on a reconstruction of it.
func natThenNode7013(t *testing.T, tree *ConfigTree) *Node {
	t.Helper()
	sec := tree.FindChild("security")
	if sec == nil {
		t.Fatal("fixture has no `security` node")
	}
	var found *Node
	var walk func(*Node)
	walk = func(n *Node) {
		if n == nil || found != nil {
			return
		}
		if len(n.Keys) > 0 && n.Keys[0] == "then" {
			found = n
			return
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(sec)
	if found == nil {
		t.Fatal("fixture has no `then` node")
	}
	return found
}

// TestDuplicateThenContainersStillCommit_7013 is the #3850 boundary, restated
// here in #7013's terms because the first version of this change broke it.
//
// Two `then` containers are last-container-wins and legal — whether they name
// the same pool or different actions — and summing occurrences across them
// reports a duplicate for a config the suite already pins as valid. The scope of
// the occurrence record is ONE container, and this is the cell that says so from
// #7013's side; TestNATTerminalActionDupIdentical3850_5628 says it from #3850's.
func TestDuplicateThenContainersStillCommit_7013(t *testing.T) {
	for _, tc := range []struct{ name, thens string }{
		{"same_pool_twice", "then { destination-nat pool PD; }\n          then { destination-nat pool PD; }"},
		{"different_pools_last_wins", "then { destination-nat pool PD; }\n          then { destination-nat pool PD2; }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			txt := `security {
  zones { security-zone untrust; }
  nat {
    destination {
      pool PD { address 10.0.0.5; }
      pool PD2 { address 10.0.0.6; }
      rule-set rs1 {
        from zone untrust;
        rule r1 {
          match { destination-address 203.0.113.10; }
          ` + tc.thens + `
        }
      }
    }
  }
}`
			tree, perr := NewParser(txt).Parse()
			if len(perr) != 0 {
				t.Fatalf("fixture did not parse: %v", perr)
			}
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("duplicate `then` containers must still commit (#3850 last-wins), got: %v.\n"+
					"The #7013 record is scoped to ONE container for exactly this reason", err)
			}
		})
	}
}

// TestSamePoolTwiceInOneBlockCommits_7013 is the redundancy boundary: naming the
// SAME pool twice in one block discards nothing, so there is nothing to report.
//
// Without this cell the gate could count raw occurrences instead of distinct
// names and every case above would still pass — it would just also reject a
// config whose meaning is unambiguous.
func TestSamePoolTwiceInOneBlockCommits_7013(t *testing.T) {
	tree := buildTree(t, natDupPoolSet7013(
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool PD pool PD"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("`pool PD pool PD` names one pool twice — nothing is discarded and the "+
			"config is unambiguous — but it was rejected: %v", err)
	}
}
