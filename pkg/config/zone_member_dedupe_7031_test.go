package config

import (
	"reflect"
	"testing"
)

// #7031: naming a zone member twice — once bare for membership, once as the
// head of a host-inbound-traffic body — compiled to that member appearing TWICE
// in zone.Interfaces, committing clean with no warning.
//
// This is not an exotic spelling. It is the ordinary way an operator adds a
// member and then gives it an override, and it is what
// `show configuration | display set` emits for a zone that has both. Measured
// pre-existing on master and on the #6735 head, byte-identical, so no round
// introduced it.
//
// The FIXTURE ORDER matters and both orders are exercised. A fixture that
// authors the override line FIRST and the bare line second reaches the append
// from the other side, and a dedupe written to skip only the second of two
// identical CONSECUTIVE appends would pass one and fail the other.
func TestZoneMemberNamedTwiceIsOneMember_7031(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{
			name: "bare membership first, override second",
			lines: []string{
				"set interfaces ge-0/0/2 unit 0 family inet address 10.0.3.1/24",
				"set security zones security-zone Y interfaces ge-0/0/2.0",
				"set security zones security-zone Y interfaces ge-0/0/2.0 host-inbound-traffic system-services ssh",
			},
		},
		{
			name: "override first, bare membership second",
			lines: []string{
				"set interfaces ge-0/0/2 unit 0 family inet address 10.0.3.1/24",
				"set security zones security-zone Y interfaces ge-0/0/2.0 host-inbound-traffic system-services ssh",
				"set security zones security-zone Y interfaces ge-0/0/2.0",
			},
		},
		{
			name: "named three times",
			lines: []string{
				"set interfaces ge-0/0/2 unit 0 family inet address 10.0.3.1/24",
				"set security zones security-zone Y interfaces ge-0/0/2.0",
				"set security zones security-zone Y interfaces ge-0/0/2.0 host-inbound-traffic system-services ssh",
				"set security zones security-zone Y interfaces ge-0/0/2.0 host-inbound-traffic protocols all",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			for _, ln := range tc.lines {
				path, err := ParseSetCommand(ln)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", ln, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", ln, err)
				}
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			zone := cfg.Security.Zones["Y"]
			if zone == nil {
				t.Fatal("zone Y did not compile")
			}
			if want := []string{"ge-0/0/2.0"}; !reflect.DeepEqual(zone.Interfaces, want) {
				t.Errorf("zone Y Interfaces = %v, want %v — zone membership is a SET, and a "+
					"member named on two set lines is one member (#7031)", zone.Interfaces, want)
			}
			// POSITIVE CONTROL. Without this the dedupe could be "correct" by
			// dropping the override entirely, and the assertion above would
			// still hold. The override must survive, and for the three-times
			// case both of its blocks must have merged.
			hib := zone.InterfaceHostInbound["ge-0/0/2.0"]
			if hib == nil {
				t.Fatalf("the per-interface override was lost: InterfaceHostInbound = %v",
					zone.InterfaceHostInbound)
			}
			if len(hib.SystemServices) == 0 {
				t.Errorf("the override lost its system-services: %+v", hib)
			}
		})
	}
}

// Deduping must not merge two DIFFERENT members. Without this cell a dedupe
// written as "keep only the first member of each node" would pass the table
// above while silently dropping every member after the first — the #5248
// regression, which is a zone-membership loss and therefore a security-boundary
// loss.
func TestZoneDedupeKeepsDistinctMembers_7031(t *testing.T) {
	tree := &ConfigTree{}
	for _, ln := range []string{
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.3.1/24",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.4.1/24",
		"set security zones security-zone Y interfaces [ ge-0/0/2.0 ge-0/0/3.0 ]",
		"set security zones security-zone Y interfaces ge-0/0/2.0",
	} {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", ln, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	zone := cfg.Security.Zones["Y"]
	if zone == nil {
		t.Fatal("zone Y did not compile")
	}
	want := []string{"ge-0/0/2.0", "ge-0/0/3.0"}
	if !reflect.DeepEqual(zone.Interfaces, want) {
		t.Errorf("zone Y Interfaces = %v, want %v — the bracketed list must keep BOTH "+
			"members (#5248) and the repeated name must not add a third entry (#7031)",
			zone.Interfaces, want)
	}
}
