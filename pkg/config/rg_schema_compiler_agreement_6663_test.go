package config

import (
	"sort"
	"testing"
)

// rgSchemaChildren returns the declared `chassis cluster redundancy-group <n>`
// child keywords from setSchema.
func rgSchemaChildren(t *testing.T) map[string]*schemaNode {
	t.Helper()
	chassis, ok := setSchema.children["chassis"]
	if !ok {
		t.Fatal("setSchema has no `chassis` node")
	}
	cluster, ok := chassis.children["cluster"]
	if !ok {
		t.Fatal("setSchema has no `chassis cluster` node")
	}
	rg, ok := cluster.children["redundancy-group"]
	if !ok {
		t.Fatal("setSchema has no `chassis cluster redundancy-group` node")
	}
	return rg.children
}

// TestRedundancyGroupCompilerAndSchemaAgree_6663 binds the two SSOTs for the
// redundancy-group grammar.
//
// `redundancyGroupStatements` is what compileChassis actually compiles;
// `setSchema` is the documented single source of truth for the config-mode
// `set`/`delete` grammar (CLAUDE.md, docs/config-schema.md) and is what drives
// completion and `?` help. #6663 found them disagreeing:
// `strict-vip-ownership` was compiled but undeclared.
//
// THE DIRECTION MATTERS, and this asserts only one of the two.
//
// compiler-implies-schema is checked, because a statement the compiler honours
// while the schema omits it is ALWAYS a defect: the redundancy-group subtree is
// open-world, so it commits and takes effect, but `set chassis cluster
// redundancy-group 1 ?` never offers it and an operator cannot discover from the
// CLI a knob that works. Silent, and only findable by reading the compiler.
//
// schema-implies-compiler is deliberately NOT checked. A leaf declared but not
// yet compiled is the project's documented accepted-only posture (#2078/#4231/
// #5804): the statement is advertised, commits, and an advisory says it is
// inert. Asserting that direction would red every deliberate use of it.
//
// Adding an entry to `redundancyGroupStatements` without declaring it in
// setSchema reds this test.
func TestRedundancyGroupCompilerAndSchemaAgree_6663(t *testing.T) {
	declared := rgSchemaChildren(t)

	var missing []string
	for kw := range redundancyGroupStatements {
		if _, ok := declared[kw]; !ok {
			missing = append(missing, kw)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("compileChassis compiles redundancy-group statement(s) %v that setSchema does "+
			"not declare. They COMMIT and take effect (the subtree is open-world), but config-mode "+
			"completion never offers them, so an operator cannot discover from the CLI a knob the "+
			"compiler implements. Declare each in pkg/config/schema_chassis.go beside `preempt`.",
			missing)
	}

	// Non-vacuity: this walk must actually be looking at the real grammar. If a
	// refactor renamed the path or emptied the table, an empty-vs-empty compare
	// would pass while checking nothing.
	if len(redundancyGroupStatements) == 0 {
		t.Fatal("redundancyGroupStatements is EMPTY — the compiler dispatch table this test " +
			"compares against is not being reached")
	}
	if len(declared) < len(redundancyGroupStatements) {
		t.Fatalf("setSchema declares %d redundancy-group children but the compiler has %d "+
			"statements; the schema lookup is probably reaching the wrong node",
			len(declared), len(redundancyGroupStatements))
	}
}

// TestStrictVIPOwnershipIsDeclaredAndCompiles_6663 is the specific #6663 case,
// asserted end-to-end rather than only through the table comparison above.
//
// The agreement test would go green if someone deleted the compiler entry
// instead of adding the schema leaf — a "fix" that removes the feature. This
// pins that the statement is BOTH declared and still compiles to its effect.
func TestStrictVIPOwnershipIsDeclaredAndCompiles_6663(t *testing.T) {
	if _, ok := rgSchemaChildren(t)["strict-vip-ownership"]; !ok {
		t.Fatal("setSchema does not declare `strict-vip-ownership` under redundancy-group, so " +
			"`set chassis cluster redundancy-group 1 ?` cannot offer it")
	}
	if _, ok := redundancyGroupStatements["strict-vip-ownership"]; !ok {
		t.Fatal("the compiler no longer handles `strict-vip-ownership` — declaring it in the " +
			"schema while dropping the compiler is not a fix, it is a feature removal")
	}

	// And it still takes effect. A valueless flag, same shape as `preempt`.
	rg := &RedundancyGroup{}
	redundancyGroupStatements["strict-vip-ownership"](rg, &Node{Keys: []string{"strict-vip-ownership"}})
	if !rg.StrictVIPOwnership {
		t.Fatal("`strict-vip-ownership` no longer sets RedundancyGroup.StrictVIPOwnership")
	}
}

// TestRedundancyGroupSchemaLeavesAreCompleteEnoughToComplete_6663 pins that
// every declared child is usable by the completion path — a leaf with no desc
// renders an empty `?` line, which is a completion gap of a different shape.
func TestRedundancyGroupSchemaLeavesAreCompleteEnoughToComplete_6663(t *testing.T) {
	for kw, node := range rgSchemaChildren(t) {
		if node == nil {
			t.Errorf("redundancy-group child %q is a nil schemaNode", kw)
			continue
		}
		if node.desc == "" {
			t.Errorf("redundancy-group child %q has an empty desc, so `?` help renders a blank "+
				"line for a statement that exists", kw)
		}
	}
}
