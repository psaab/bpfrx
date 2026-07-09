package config

import (
	"strings"
	"testing"
)

// TestInterfaceRangeExpandsMembers is the #4027 RED-on-revert guard: an
// `interfaces interface-range <name>` stanza must expand into its member
// interfaces (each getting the range's shared config) and must NOT mint a
// phantom interface named after the range. Before the fix the range name was
// compiled as a real interface (phantom, later brought admin-down) and the
// shared config + members were dropped — this test goes RED on that behavior.
func TestInterfaceRangeExpandsMembers(t *testing.T) {
	tree := setTree(t,
		"set interfaces interface-range uplinks member ge-0/0/1",
		"set interfaces interface-range uplinks member ge-0/0/2",
		"set interfaces interface-range uplinks mtu 9000",
		// A normal interface, unrelated to the range: must be unaffected.
		"set interfaces ge-0/0/3 mtu 1500",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifaces := cfg.Interfaces.Interfaces

	// No phantom interface for the range name (in either spelling).
	if _, ok := ifaces["interface-range"]; ok {
		t.Errorf("phantom interface %q was created for the range name", "interface-range")
	}
	if _, ok := ifaces["uplinks"]; ok {
		t.Errorf("phantom interface %q was created for the range name", "uplinks")
	}

	// Both members exist and carry the range's shared MTU.
	for _, m := range []string{"ge-0/0/1", "ge-0/0/2"} {
		ifc, ok := ifaces[m]
		if !ok {
			t.Errorf("member %s not compiled from the interface-range", m)
			continue
		}
		if ifc.Disable {
			t.Errorf("member %s must not be admin-down", m)
		}
		if ifc.MTU != 9000 {
			t.Errorf("member %s MTU = %d, want 9000 (range shared config)", m, ifc.MTU)
		}
	}

	// The unrelated normal interface is unchanged.
	if ge3, ok := ifaces["ge-0/0/3"]; !ok {
		t.Errorf("normal interface ge-0/0/3 missing")
	} else if ge3.MTU != 1500 {
		t.Errorf("ge-0/0/3 MTU = %d, want 1500 (unchanged)", ge3.MTU)
	}
}

// TestInterfaceRangeSharedUnitAndPrecedence checks that shared config is
// deep-applied (unit/family addresses reach each member) and that a member's
// own per-interface statements win over the shared value on a scalar conflict
// while additive statements (addresses) accumulate.
func TestInterfaceRangeSharedUnitAndPrecedence(t *testing.T) {
	tree := setTree(t,
		"set interfaces interface-range R member ge-0/0/1",
		"set interfaces interface-range R member ge-0/0/2",
		"set interfaces interface-range R mtu 9000",
		"set interfaces interface-range R unit 0 family inet address 10.5.5.5/24",
		// ge-0/0/1 overrides mtu and adds its own address.
		"set interfaces ge-0/0/1 mtu 1400",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.9.9.9/24",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifaces := cfg.Interfaces.Interfaces

	ge1 := ifaces["ge-0/0/1"]
	if ge1 == nil {
		t.Fatalf("ge-0/0/1 missing")
	}
	// Member's own mtu 1400 wins over the shared 9000.
	if ge1.MTU != 1400 {
		t.Errorf("ge-0/0/1 MTU = %d, want 1400 (member override wins)", ge1.MTU)
	}
	// Both the shared and the member's own address accumulate.
	if u0 := ge1.Units[0]; u0 == nil {
		t.Errorf("ge-0/0/1 unit 0 missing")
	} else {
		if !containsStr(u0.Addresses, "10.5.5.5/24") {
			t.Errorf("ge-0/0/1 missing shared address 10.5.5.5/24; have %v", u0.Addresses)
		}
		if !containsStr(u0.Addresses, "10.9.9.9/24") {
			t.Errorf("ge-0/0/1 missing own address 10.9.9.9/24; have %v", u0.Addresses)
		}
	}

	ge2 := ifaces["ge-0/0/2"]
	if ge2 == nil {
		t.Fatalf("ge-0/0/2 missing")
	}
	if ge2.MTU != 9000 {
		t.Errorf("ge-0/0/2 MTU = %d, want 9000 (shared)", ge2.MTU)
	}
	if u0 := ge2.Units[0]; u0 == nil || !containsStr(u0.Addresses, "10.5.5.5/24") {
		t.Errorf("ge-0/0/2 missing shared address 10.5.5.5/24")
	}
}

// TestInterfaceRangeHierarchical exercises the braced (hierarchical) AST shape
// produced by the file parser, not just the flat-set replay path.
func TestInterfaceRangeHierarchical(t *testing.T) {
	input := `
interfaces {
    interface-range R {
        member ge-0/0/1;
        member ge-0/0/2;
        mtu 9000;
        unit 0 {
            family inet {
                address 10.5.5.5/24;
            }
        }
    }
    ge-0/0/3 {
        mtu 1500;
    }
}
`
	tree, errs := NewParser(input).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifaces := cfg.Interfaces.Interfaces
	if _, ok := ifaces["interface-range"]; ok {
		t.Errorf("phantom interface-range interface created (hierarchical)")
	}
	for _, m := range []string{"ge-0/0/1", "ge-0/0/2"} {
		ifc := ifaces[m]
		if ifc == nil {
			t.Errorf("member %s missing (hierarchical)", m)
			continue
		}
		if ifc.MTU != 9000 {
			t.Errorf("member %s MTU = %d, want 9000 (hierarchical shared)", m, ifc.MTU)
		}
		if u0 := ifc.Units[0]; u0 == nil || !containsStr(u0.Addresses, "10.5.5.5/24") {
			t.Errorf("member %s missing shared address (hierarchical)", m)
		}
	}
	if ge3 := ifaces["ge-0/0/3"]; ge3 == nil || ge3.MTU != 1500 {
		t.Errorf("normal ge-0/0/3 changed by hierarchical range expansion")
	}
}

// TestInterfaceRangeMemberRange expands the `member-range <start> to <end>`
// selector into each interface in the numeric range.
func TestInterfaceRangeMemberRange(t *testing.T) {
	tree := setTree(t,
		"set interfaces interface-range R member-range ge-0/0/1 to ge-0/0/3",
		"set interfaces interface-range R mtu 9000",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifaces := cfg.Interfaces.Interfaces
	for _, m := range []string{"ge-0/0/1", "ge-0/0/2", "ge-0/0/3"} {
		if ifc := ifaces[m]; ifc == nil {
			t.Errorf("member-range member %s not expanded", m)
		} else if ifc.MTU != 9000 {
			t.Errorf("member-range member %s MTU = %d, want 9000", m, ifc.MTU)
		}
	}
}

// TestInterfaceRangeMultipleRangesFlatSet checks that two distinct range names
// under the single flat-set interface-range node are kept separate.
func TestInterfaceRangeMultipleRangesFlatSet(t *testing.T) {
	tree := setTree(t,
		"set interfaces interface-range r1 member ge-0/0/1",
		"set interfaces interface-range r1 mtu 9000",
		"set interfaces interface-range r2 member ge-0/0/2",
		"set interfaces interface-range r2 mtu 1400",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifaces := cfg.Interfaces.Interfaces
	if ge1 := ifaces["ge-0/0/1"]; ge1 == nil || ge1.MTU != 9000 {
		t.Errorf("r1 member ge-0/0/1 MTU wrong: %+v", ge1)
	}
	if ge2 := ifaces["ge-0/0/2"]; ge2 == nil || ge2.MTU != 1400 {
		t.Errorf("r2 member ge-0/0/2 MTU wrong: %+v", ge2)
	}
	if _, ok := ifaces["r1"]; ok {
		t.Errorf("phantom r1 interface")
	}
	if _, ok := ifaces["r2"]; ok {
		t.Errorf("phantom r2 interface")
	}
}

// TestInterfaceRangeNoStanzaUnchanged asserts the pass is a no-op for a config
// with no interface-range: a plain interface compiles bit-identically.
func TestInterfaceRangeNoStanzaUnchanged(t *testing.T) {
	tree := setTree(t,
		"set interfaces ge-0/0/0 mtu 1500",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.MTU != 1500 {
		t.Fatalf("plain interface disturbed: %+v", ifc)
	}
	if u0 := ifc.Units[0]; u0 == nil || !containsStr(u0.Addresses, "10.0.0.1/24") {
		t.Fatalf("plain interface unit 0 address lost")
	}
}

// TestInterfaceRangeMemberRangeHugeEndOverflow is the #4807 RED-on-revert
// guard: a member-range whose end value is a trailing integer near
// math.MaxInt64 must be rejected with a clean warning, not panic the
// compiler. Before the fix, `en-sn+1` (both plain `int`, 64-bit on amd64)
// overflowed to a large negative number for this input, which (a) beat the
// `en-sn+1 > interfaceRangeMaxMembers` guard (a negative number is never
// greater than 4096) and (b) reached `make([]string, 0, en-sn+1)` with a
// negative capacity, panicking with "runtime error: makeslice: cap out of
// range" and crashing the whole daemon on every future compile of this
// config (boot-time load included — no strict/lenient gate covers this
// prewalk pass). This test goes RED on that overflow behavior.
func TestInterfaceRangeMemberRangeHugeEndOverflow(t *testing.T) {
	tree := setTree(t,
		"set interfaces interface-range R member-range ge-0/0/0 to ge-0/0/9223372036854775807",
		"set interfaces interface-range R mtu 9000",
	)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig returned an error instead of a clean warning: %v", err)
	}

	// Must not have expanded into millions/billions of phantom members.
	if n := len(cfg.Interfaces.Interfaces); n > interfaceRangeMaxMembers {
		t.Fatalf("member-range expanded to %d interfaces, want <= %d (cap)",
			n, interfaceRangeMaxMembers)
	}

	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "exceeds") && strings.Contains(w, "interfaces") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a member-range-exceeds-cap warning, got: %v", cfg.Warnings)
	}
}

// TestExpandMemberRangeHugeEndDoesNotOverflow directly exercises
// expandMemberRange (the #4807 unit) with the exact overflow-triggering
// inputs from the issue: start "ge-0/0/0", end "ge-0/0/9223372036854775807".
// Before the fix this panicked inside make(); it must now return a nil
// member list and a warning.
func TestExpandMemberRangeHugeEndDoesNotOverflow(t *testing.T) {
	members, warnings := expandMemberRange("R", []string{"ge-0/0/0", "to", "ge-0/0/9223372036854775807"})
	if members != nil {
		t.Errorf("expandMemberRange with overflow-triggering end returned %d members, want none", len(members))
	}
	if len(warnings) == 0 {
		t.Errorf("expandMemberRange with overflow-triggering end returned no warning")
	}
}
