package config

import (
	"strings"
	"testing"
)

// #7029: Junos permits `apply-groups`, `apply-groups-except` and `apply-macro`
// at ANY point in the hierarchy. ExpandGroups removes only `apply-groups` — the
// other two survive expansion as live nodes — so in a slot whose children are
// read as NAMES they compiled as phantom instances.
//
// In the `security zones security-zone <z> interfaces` member slot that made
// the zone-interface-DEFINED gate reject the commit:
//
//	REJECT security zone "Z" references interface "apply-groups-except",
//	which is not defined under `interfaces` ...
//
// Fail-LOUD over-rejection rather than a silent membership loss — but it
// refuses a legal Junos config, and the operator's only clue names a keyword
// they did not intend as an interface.
func TestApplyMetaInZoneInterfaceMemberSlotCompiles_7029(t *testing.T) {
	for _, meta := range []string{
		"apply-groups-except G;",
		"apply-macro M { key value; }",
		// Nested body, since apply-macro's contents are arbitrary and the walk
		// must not descend into them looking for members either.
		"apply-macro M { ge-0/0/9.0 something; }",
	} {
		t.Run(meta, func(t *testing.T) {
			src := `
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones { security-zone Z { interfaces {
` + meta + `
  ge-0/0/0.0;
} } } }
`
			tree, errs := NewParser(src).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig REJECTED a legal Junos config carrying %q in the member "+
					"slot: %v", meta, err)
			}
			zone := cfg.Security.Zones["Z"]
			if zone == nil {
				t.Fatal("zone Z did not compile")
			}
			// POSITIVE CONTROL. Skipping the meta statement must not skip the
			// real member beside it — a walk that returned early on the first
			// meta node would satisfy the "no rejection" assertion above while
			// emptying the zone, which is a security-boundary loss.
			want := []string{"ge-0/0/0.0"}
			if len(zone.Interfaces) != 1 || zone.Interfaces[0] != want[0] {
				t.Errorf("zone Z Interfaces = %v, want %v — the real member must survive beside "+
					"the meta statement", zone.Interfaces, want)
			}
			// And the meta keyword itself must not have become a member under
			// any spelling.
			for _, name := range zone.Interfaces {
				if strings.HasPrefix(name, "apply-") {
					t.Errorf("zone Z carries %q as an interface member (#7029)", name)
				}
			}
		})
	}
}

// The CENSUS, kept as a guard rather than reported once and discarded.
//
// The issue named one slot. Every slot below reads its children as instance
// NAMES, so every one could carry the same defect; measured at
// `origin/master`, exactly ONE did — which is what makes this table a real
// negative rather than an untested assumption.
//
// It is also the proof that the table is not blind: run it against master's
// compiler_security_zones.go and the zone-interfaces row REJECTS while the
// other seven accept. A census in which nothing ever fails is indistinguishable
// from a census that cannot see.
func TestApplyMetaIsAcceptedInEveryNamedInstanceSlot_7029(t *testing.T) {
	for name, src := range map[string]string{
		"zone interfaces": `
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones { security-zone Z { interfaces { apply-macro M { k v; } ge-0/0/0.0; } } } }
`,
		"security zones (zone-name slot)": `
security { zones { apply-macro M { k v; } security-zone Z { } } }
`,
		"security policies from-zone": `
security { zones { security-zone A { } security-zone B { } }
  policies { apply-macro M { k v; }
    from-zone A to-zone B { policy P { match { source-address any; destination-address any; application any; } then { permit; } } } } }
`,
		"address-book entries": `
security { zones { security-zone A { address-book { apply-macro M { k v; } address H 10.0.0.1/32; } } } }
`,
		"applications": `
applications { apply-macro M { k v; } application APP { protocol tcp; destination-port 80; } }
`,
		"interfaces stanza": `
interfaces { apply-macro M { k v; } ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
`,
		"firewall filters": `
firewall { family inet { filter F { apply-macro M { k v; } term T { then accept; } } } }
`,
		"routing-instances": `
routing-instances { apply-macro M { k v; } RI { instance-type virtual-router; } }
`,
	} {
		t.Run(name, func(t *testing.T) {
			tree, errs := NewParser(src).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			if _, err := CompileConfig(tree); err != nil {
				t.Errorf("`apply-macro` in the %s slot rejects the commit; Junos permits it at any "+
					"hierarchy point and ExpandGroups does not remove it (#7029): %v", name, err)
			}
		})
	}
}

// A meta statement nested UNDER a member, which reaches a different guard.
//
// A meta statement reaches the guard by two different routes, and this fixture
// is the second: at the top of the stanza it arrives as the member NODE, and
// nested under a real member it arrives as a CHILD and comes back to the same
// guard through the recursion.
//
// The distinction was measured rather than assumed. A second check in the child
// loop was written first — "two guards" — then instrumented: it IS reached by
// this fixture, and removing it changes no outcome, because the recursion lands
// on the head guard anyway. It was a redundant branch dressed up as a guard and
// was removed. This test stays: the nested shape must keep compiling however
// the walk is later restructured.
func TestApplyMetaNestedUnderAMemberCompiles_7029(t *testing.T) {
	src := `
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones { security-zone Z { interfaces {
  ge-0/0/0.0 { apply-macro M { key value; } }
} } } }
`
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig REJECTED a member carrying a nested apply-macro: %v", err)
	}
	zone := cfg.Security.Zones["Z"]
	if zone == nil {
		t.Fatal("zone Z did not compile")
	}
	// The member must survive AND the macro must not have become a second one.
	if len(zone.Interfaces) != 1 || zone.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("zone Z Interfaces = %v, want [ge-0/0/0.0] — a nested meta statement must be "+
			"skipped without taking its parent member with it (#7029)", zone.Interfaces)
	}
}
