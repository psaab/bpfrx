package config

import (
	"strings"
	"testing"
)

// Regression tests for #3332: trailing tokens on a SUPPORTED fixed-arity
// scalar value leaf were silently consumed at commit. `set interfaces
// ge-0-0-0 description hello bogus` parses (flat-set) as a `description`
// leaf carrying its single value `hello` with a trailing CHILD node
// `bogus` that the compiler never reads — so the typo committed cleanly
// and the operator's garbage token was dropped without warning.
//
// The #3411 screen subset closed only the screen subtree (compileScreen
// recordKeyExtras). This is the general schema-walk value-arity gate
// (SchemaValidate via isScalarValueLeaf): any fixed-arity scalar value
// leaf (args > 0, children == nil, non-multi, untyped) now rejects a
// trailing token its declared arity does not expect, while multi /
// bracketed-list (#2419) and named-instance leaves stay accepted.
//
// All tests build the tree through the production ParseSetCommand +
// SetPath loop (never NewParser — see CLAUDE.md "Testing flat set
// syntax").

func buildSetTree3332(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
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

// TestSchema3332_TrailingTokenOnScalarLeaf_Rejected is the RED-on-revert
// guard: a scalar value leaf carrying a trailing junk token must fail the
// commit-time schema gate. Reverting the isScalarValueLeaf gate makes the
// token silently accepted and this test goes RED.
func TestSchema3332_TrailingTokenOnScalarLeaf_Rejected(t *testing.T) {
	tree := buildSetTree3332(t,
		"set interfaces ge-0-0-0 description hello bogus",
	)
	err := SchemaValidate(tree, nil)
	if err == nil {
		t.Fatal("expected commit error for trailing token on `description` scalar leaf, got nil (token silently dropped)")
	}
	if !strings.Contains(err.Error(), "description") || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("error should reference the leaf + the offending token: %v", err)
	}
}

// TestSchema3332_ValidScalarLeaf_Accepted guards against a false-reject of
// the legitimate single-value spelling.
func TestSchema3332_ValidScalarLeaf_Accepted(t *testing.T) {
	tree := buildSetTree3332(t,
		"set interfaces ge-0-0-0 description hello",
	)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("unexpected error for valid scalar leaf: %v", err)
	}
}

// TestSchema3332_MultiValueLeaf_Accepted guards the #2419 exemption: a
// multi-value leaf legitimately carries multiple trailing values and must
// NOT be rejected by the arity gate.
func TestSchema3332_MultiValueLeaf_Accepted(t *testing.T) {
	tree := buildSetTree3332(t,
		"set system name-server 8.8.8.8",
		"set system name-server 9.9.9.9",
	)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("unexpected error for multi-value leaf: %v", err)
	}
	// And the bracketed-list collapse spelling (a single set line with
	// several values on one multi leaf).
	tree2 := buildSetTree3332(t,
		"set security zones security-zone trust address-book address web 10.0.0.0/24",
	)
	if err := SchemaValidate(tree2, nil); err != nil {
		t.Fatalf("unexpected error for multi-value address leaf: %v", err)
	}
}

// TestSchema3332_OpaqueContainerBody_Accepted guards the design decision
// behind the explicit `scalar` opt-in: `application-set` is `args:1,
// children:nil` (structurally identical to a scalar value leaf) but is an
// OPAQUE CONTAINER whose `application <member>` body the compiler reads off
// the node's AST children. A structural-only gate would false-reject the
// legitimate body; the gate must stay out unless the leaf is tagged
// `scalar: true`. If someone tags application-set scalar (or drops the
// children==nil guard), this test goes RED.
func TestSchema3332_OpaqueContainerBody_Accepted(t *testing.T) {
	tree := buildSetTree3332(t,
		"set applications application-set my-set application junos-http",
		"set applications application-set my-set application junos-https",
	)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("unexpected error for opaque application-set body: %v", err)
	}
}

// TestSchema3332_NamedInstanceLeaf_Accepted guards the named-instance
// exemption: a container leaf whose trailing tokens are real sub-structure
// (here the `address <cidr> { ... }` identity arg) must not trip the gate.
func TestSchema3332_NamedInstanceLeaf_Accepted(t *testing.T) {
	tree := buildSetTree3332(t,
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.1.1/24",
	)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("unexpected error for named-instance address leaf: %v", err)
	}
}
