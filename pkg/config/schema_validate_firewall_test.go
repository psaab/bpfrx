package config_test

// #1319 PR 3 — firewall `then forwarding-class` tree-based cross-ref.
// The validator resolves references against the forwarding-class
// definitions collected from the SAME tree (collectSchemaRefs), because
// the production SchemaValidate call sites pass cfg=nil (validation runs
// before compile). The end-to-end production-path proof (Store
// CommitCheck / Load / SyncApply) lives in
// pkg/configstore/typed_leaf_lenient_test.go; these tests pin the
// validator + walker semantics at the pkg/config layer.

import (
	"strings"
	"testing"
)

func TestSchemaValidate_FirewallForwardingClass_RejectsDangling(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		err := flatSchemaCheck(t,
			"set firewall family "+family+" filter f1 term t1 then forwarding-class no-such-class")
		if err == nil {
			t.Fatalf("family %s: expected dangling forwarding-class to reject, got nil", family)
		}
		if !strings.Contains(err.Error(), "forwarding-class") ||
			!strings.Contains(err.Error(), "no-such-class") {
			t.Fatalf("family %s: error should name the leaf and the dangling class: %v", family, err)
		}
	}
}

// Atomicity: the definition and the reference arrive in the same tree —
// the reference must validate against the candidate's own definitions,
// not against any previously compiled state.
func TestSchemaValidate_FirewallForwardingClass_SameTreeDefinitionPasses(t *testing.T) {
	if err := flatSchemaCheck(t,
		"set class-of-service forwarding-classes queue 5 iperf-video",
		"set firewall family inet filter f1 term t1 then forwarding-class iperf-video",
	); err != nil {
		t.Fatalf("same-tree definition + reference must pass, got: %v", err)
	}
}

// best-effort is always resolvable: with no forwarding-classes
// configured the dataplane synthesizes a best-effort queue.
func TestSchemaValidate_FirewallForwardingClass_BestEffortAlwaysAccepted(t *testing.T) {
	if err := flatSchemaCheck(t,
		"set firewall family inet filter f1 term t1 then forwarding-class best-effort",
	); err != nil {
		t.Fatalf("best-effort must always be accepted, got: %v", err)
	}
}

// The other Junos default classes are NOT implicitly defined by the xpf
// runtime — referencing them undefined is the silent no-op this gate
// closes.
func TestSchemaValidate_FirewallForwardingClass_JunosDefaultsNotImplicit(t *testing.T) {
	err := flatSchemaCheck(t,
		"set firewall family inet filter f1 term t1 then forwarding-class expedited-forwarding")
	if err == nil {
		t.Fatal("expedited-forwarding without a definition must reject, got nil")
	}
}

// A definition living in a group body satisfies a reference: the refs
// collection is deliberately permissive (union of main tree + all group
// bodies), so node-variable configs whose definitions sit in groups
// never false-reject — whether or not this walk sees the tree pre- or
// post-expansion.
func TestSchemaValidate_FirewallForwardingClass_GroupDefinitionSatisfies(t *testing.T) {
	if err := flatSchemaCheck(t,
		"set groups cos-common class-of-service forwarding-classes queue 5 iperf-video",
		"set apply-groups cos-common",
		"set firewall family inet filter f1 term t1 then forwarding-class iperf-video",
	); err != nil {
		t.Fatalf("group-body definition must satisfy the reference, got: %v", err)
	}
}

// Hierarchical shape parity for both directions.
func TestSchemaValidate_FirewallForwardingClass_Hierarchical(t *testing.T) {
	if err := schemaCheck(t, `class-of-service {
    forwarding-classes {
        queue 5 iperf-video;
    }
}
firewall {
    family inet {
        filter f1 {
            term t1 {
                then {
                    forwarding-class iperf-video;
                }
            }
        }
    }
}`); err != nil {
		t.Fatalf("hierarchical definition + reference must pass, got: %v", err)
	}

	err := schemaCheck(t, `firewall {
    family inet6 {
        filter f6 {
            term t1 {
                then {
                    forwarding-class missing-class;
                }
            }
        }
    }
}`)
	if err == nil {
		t.Fatal("hierarchical dangling reference must reject, got nil")
	}
	if !strings.Contains(err.Error(), "missing-class") {
		t.Fatalf("error should name the dangling class: %v", err)
	}
}

// A forwarding-classes entry whose queue number does not parse is
// skipped by the compiler, so it must NOT satisfy a reference (the
// collection mirrors compileClassOfService).
func TestSchemaValidate_FirewallForwardingClass_UncompiledDefinitionDoesNotSatisfy(t *testing.T) {
	err := flatSchemaCheck(t,
		"set class-of-service forwarding-classes queue asd iperf-video",
		"set firewall family inet filter f1 term t1 then forwarding-class iperf-video",
	)
	if err == nil {
		t.Fatal("a definition the compiler skips must not satisfy the reference, got nil")
	}
}
