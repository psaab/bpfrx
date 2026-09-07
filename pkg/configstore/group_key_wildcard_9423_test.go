package configstore

import (
	"sort"
	"strings"
	"testing"
)

// #9423, the OPERATOR channel — and the reason the interfaces example in the
// issue understates where the defect is reachable.
//
// Measured on the base revision, the channels did NOT agree, and they disagreed
// by SLOT rather than by pattern:
//
//	slot                  CompileConfig    configstore.CheckText
//	interfaces <ge-*>     ACCEPT+phantom   REJECT
//	security-zone <tr*>   ACCEPT+phantom   ACCEPT + a phantom zone named `<tr*>`
//
// `CheckText` caught the interface case only because the typed interface-name
// validator rejects `<` as a NAME character — an incidental downstream refusal,
// not the group matcher working. A slot whose instance name has no such
// validator carried the phantom all the way through the operator commit path
// with zero warnings. A probe on the interfaces slot alone would have concluded
// the commit path was already safe.

func zoneWildcardSrc9423(pattern string) string {
	return `system { host-name p; }
groups { G { security { zones { security-zone ` + pattern + ` { description FROM-GROUP; } } } } }
apply-groups G;
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }`
}

func TestGroupKeyWildcardNoPhantomZoneAtCommit9423(t *testing.T) {
	cases := []struct {
		pattern     string
		wantApplied bool
	}{
		{"<*>", true},   // POSITIVE CONTROL: the universal token has always worked
		{"<tr*>", true}, // the partial glob now reaches the real zone
		{"<dmz*>", false},
	}
	for _, tc := range cases {
		cfg, err := CheckText(zoneWildcardSrc9423(tc.pattern), -1)
		if err != nil {
			t.Fatalf("%s: rejected by the operator commit path: %v", tc.pattern, err)
		}
		var names []string
		for z := range cfg.Security.Zones {
			names = append(names, z)
		}
		sort.Strings(names)
		for _, n := range names {
			if strings.ContainsAny(n, "<>*") {
				t.Fatalf("%s: a PHANTOM zone reached the operator commit path: zones=%v "+
					"— a zone that can never exist, referenceable by name from a policy "+
					"(#9423)", tc.pattern, names)
			}
		}
		if len(names) != 1 || names[0] != "trust" {
			t.Fatalf("%s: authored zones changed: %v", tc.pattern, names)
		}
		applied := cfg.Security.Zones["trust"].Description == "FROM-GROUP"
		if applied != tc.wantApplied {
			t.Fatalf("%s: template applied=%v, want %v (description=%q)",
				tc.pattern, applied, tc.wantApplied, cfg.Security.Zones["trust"].Description)
		}
	}
}

// The interfaces slot: the phantom is gone at the matcher, so the incidental
// downstream name validator is no longer what saves the commit. Asserted as an
// ACCEPT with the template applied, which the base revision could not produce
// for a partial glob on any channel.
func TestGroupKeyWildcardInterfaceAppliesAtCommit9423(t *testing.T) {
	cfg, err := CheckText(`system { host-name p; }
groups { G { interfaces { <ge-*> { description FROM-GROUP; } } } }
apply-groups G;
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
  xe-1/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } }
}`, -1)
	if err != nil {
		t.Fatalf("rejected by the operator commit path: %v", err)
	}
	if got := cfg.Interfaces.Interfaces["ge-0/0/0"].Description; got != "FROM-GROUP" {
		t.Fatalf("the `<ge-*>` template did not reach ge-0/0/0: description=%q", got)
	}
	if got := cfg.Interfaces.Interfaces["xe-1/0/0"].Description; got != "" {
		t.Fatalf("the `<ge-*>` template reached a NON-matching interface: description=%q", got)
	}
	if len(cfg.Interfaces.Interfaces) != 2 {
		t.Fatalf("phantom interface: %d interfaces", len(cfg.Interfaces.Interfaces))
	}
}
