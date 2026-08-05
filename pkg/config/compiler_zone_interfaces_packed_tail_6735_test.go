package config

import (
	"reflect"
	"strings"
	"testing"
)

// Tests for #6735: a `security zones security-zone <z> interfaces` member whose
// Keys carry `host-inbound-traffic` with FURTHER TOKENS AFTER IT.
//
// The lexer strips brackets (#2419), so these two statements are structurally
// identical by the time the compiler sees them:
//
//	interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ];   // member list
//	interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh;  // packed body
//
// and their readings DISAGREE about zone membership. zoneInterfaceKeysBeforeBody
// truncates at the keyword, so the first silently loses member `ge-0/0/1.0` —
// a valid, defined interface the operator put in this zone, left with Zone == ""
// so the dataplane never binds it and no policy naming the zone applies to its
// traffic — and the second silently loses the whole override. The #6525
// non-empty belt cannot see the first: one member survived, so the stanza is not
// empty.
//
// The resolution is refusal, not a guess: reject at commit, warn on the tolerant
// path, and point the operator at the block spelling, which is unambiguous.

// zonePackedTailConfig wraps a zone stanza in a config that DEFINES both
// interfaces the tests reference, so a rejection can only come from the gate
// under test and never from the zone-interface-DEFINED gate.
func zonePackedTailConfig(stanza string) string {
	return `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet {
                address 10.0.1.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone Z {
            ` + stanza + `
        }
    }
}`
}

// TestZoneInterfaces6735PackedTailRejectedAndPositiveControl holds BOTH tables
// in one function on purpose. A rejection test alone cannot distinguish
// "rejects the ambiguous statement" from "rejects everything" — the accept
// table is what makes the reject table mean something, and keeping them in one
// test means neither can be deleted or skipped without the other.
func TestZoneInterfaces6735PackedTailRejectedAndPositiveControl(t *testing.T) {
	t.Run("rejected", func(t *testing.T) {
		cases := []struct {
			name     string
			stanza   string
			wantLost string // the token(s) the truncator would have silently dropped
		}{
			{
				// The #6735 defect proper: a valid member AFTER the keyword.
				name:     "bracket list with a body keyword mid-list",
				stanza:   `interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ];`,
				wantLost: "ge-0/0/1.0",
			},
			{
				// Same shape, read the other way: the override is what is lost.
				name:     "compact packed body on the stanza Keys",
				stanza:   `interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh;`,
				wantLost: "system-services ssh",
			},
			{
				// Block spelling, packed onto the MEMBER's Keys — the recursion
				// must reach member nodes, not just the synthesized compact one.
				name:     "block member with a packed body on its Keys",
				stanza:   `interfaces { ge-0/0/0.0 host-inbound-traffic system-services ssh; }`,
				wantLost: "system-services ssh",
			},
			{
				// Keyword FIRST: nothing precedes it, so this also compiles to
				// zero members and the #6525 non-empty gate would fire too. The
				// packed-tail gate runs first precisely so the operator is told
				// about the token that was dropped rather than "names no
				// interface", which would be true but misdirecting.
				name:     "keyword first, member after",
				stanza:   `interfaces host-inbound-traffic ge-0/0/1.0;`,
				wantLost: "ge-0/0/1.0",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				tree := parseHierarchical(t, zonePackedTailConfig(tc.stanza))
				_, err := CompileConfig(tree)
				if err == nil {
					t.Fatalf("CompileConfig ACCEPTED the ambiguous stanza %q; the truncator silently keeps only the names before `host-inbound-traffic`, so %q is dropped (#6735)",
						tc.stanza, tc.wantLost)
				}
				for _, want := range []string{`"Z"`, "host-inbound-traffic", tc.wantLost} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("reject error %q does not name %q — the message must identify the zone, the keyword, and the tokens that would have been dropped (#6735)",
							err.Error(), want)
					}
				}
			})
		}
	})

	// POSITIVE CONTROL. Every spelling here is unambiguous and must still
	// compile. Without this table a gate that rejected every `interfaces`
	// stanza — or a members reader that always returned nil — would pass the
	// reject table above unnoticed.
	t.Run("still compiles", func(t *testing.T) {
		cases := []struct {
			name   string
			stanza string
			want   []string
		}{
			{
				name:   "single compact member",
				stanza: `interfaces ge-0/0/0.0;`,
				want:   []string{"ge-0/0/0.0"},
			},
			{
				name:   "bracket list with no body keyword",
				stanza: `interfaces [ ge-0/0/0.0 ge-0/0/1.0 ];`,
				want:   []string{"ge-0/0/0.0", "ge-0/0/1.0"},
			},
			{
				name:   "block members",
				stanza: `interfaces { ge-0/0/0.0; ge-0/0/1.0; }`,
				want:   []string{"ge-0/0/0.0", "ge-0/0/1.0"},
			},
			{
				// Body as a CHILD node — unambiguous, and the override still
				// compiles. This is the spelling the reject message recommends,
				// so it had better work.
				name:   "member with a body block",
				stanza: `interfaces ge-0/0/0.0 { host-inbound-traffic { system-services ssh; } }`,
				want:   []string{"ge-0/0/0.0"},
			},
			{
				name:   "bracket members with a shared body block",
				stanza: `interfaces [ ge-0/0/0.0 ge-0/0/1.0 ] { host-inbound-traffic { system-services ssh; } }`,
				want:   []string{"ge-0/0/0.0", "ge-0/0/1.0"},
			},
			{
				// Keyword with NOTHING after it: truncation loses nothing, so
				// rejecting would be the #4191 over-rejection class.
				name:   "keyword last, empty body",
				stanza: `interfaces ge-0/0/0.0 host-inbound-traffic;`,
				want:   []string{"ge-0/0/0.0"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				tree := parseHierarchical(t, zonePackedTailConfig(tc.stanza))
				cfg, err := CompileConfig(tree)
				if err != nil {
					t.Fatalf("CompileConfig REJECTED the unambiguous stanza %q: %v — the packed-tail gate must fire only when a body keyword has tokens AFTER it (#6735/#4191)",
						tc.stanza, err)
				}
				if got := cfg.Security.Zones["Z"].Interfaces; !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("stanza %q compiled membership %v, want %v", tc.stanza, got, tc.want)
				}
			})
		}
	})
}

// TestZoneInterfaces6735FlatSetReachesThePackedTail is the reachability
// correction. #6525 documented its compact-leaf defect as hierarchical-ingest
// only — "NOT reachable from the `set` CLI" — and that is true OF THAT SHAPE.
// It is NOT true of this one. `set` DOES reach the packed tail, because SetPath
// descends the interface-name wildcard for the first bracket token and then
// collapses the remaining tokens onto ONE nested leaf, keyword and all:
//
//	set ... interfaces [ ge-0/0/0.0 ge-0/0/1.0 host-inbound-traffic ge-0/0/2.0 ]
//
//	interfaces
//	  ge-0/0/0.0
//	    Keys=["ge-0/0/1.0","host-inbound-traffic","ge-0/0/2.0"]   <- nested leaf
//
// so the truncator runs on a NESTED member and `ge-0/0/2.0` is dropped. That
// makes this defect reachable from the ordinary operator CLI, not just from
// `load override` / the persisted file / HA SyncApply.
//
// This is also the test that binds the CHILD RECURSION in
// zoneInterfaceMemberPackedTail. Measured: with the recursion deleted, every
// other case in this file still passes — the stanza-level loop already checks
// each block member's own Keys — so without this case the recursion would be
// unbound decoration that a later cleanup could delete silently.
func TestZoneInterfaces6735FlatSetReachesThePackedTail(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *ConfigTree {
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

	t.Run("the nested leaf really does carry the keyword", func(t *testing.T) {
		tree := build(t, "set security zones security-zone Z interfaces [ ge-0/0/0.0 ge-0/0/1.0 host-inbound-traffic ge-0/0/2.0 ]")
		zonesNode := tree.FindChild("security").FindChild("zones")
		examined := 0
		for _, inst := range namedInstances(zonesNode.FindChildren("security-zone")) {
			for _, prop := range inst.node.Children {
				if prop.Name() != "interfaces" {
					continue
				}
				examined++
				kw, tail, ok := zoneInterfaceStanzaPackedTail(prop)
				if !ok {
					t.Fatalf("detector missed a `set`-authored packed tail; stanza Keys=%v — the child recursion is what finds it", prop.Keys)
				}
				if kw != "host-inbound-traffic" {
					t.Fatalf("detector reported keyword %q, want host-inbound-traffic", kw)
				}
				if !reflect.DeepEqual(tail, []string{"ge-0/0/2.0"}) {
					t.Fatalf("detector reported lost tail %v, want [ge-0/0/2.0]", tail)
				}
			}
		}
		if examined == 0 {
			t.Fatalf("no `interfaces` stanza examined; this subtest asserted nothing")
		}
	})

	t.Run("membership really does lose the trailing member", func(t *testing.T) {
		tree := build(t, "set security zones security-zone Z interfaces [ ge-0/0/0.0 ge-0/0/1.0 host-inbound-traffic ge-0/0/2.0 ]")
		zonesNode := tree.FindChild("security").FindChild("zones")
		secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
		if err := compileZones(zonesNode, secCfg); err != nil {
			t.Fatalf("compileZones: %v", err)
		}
		want := []string{"ge-0/0/0.0", "ge-0/0/1.0"}
		if got := secCfg.Zones["Z"].Interfaces; !reflect.DeepEqual(got, want) {
			t.Fatalf("membership = %v, want %v — this PINS the `set`-reachable loss (ge-0/0/2.0 dropped) the gate rejects", got, want)
		}
	})

	t.Run("control: the same list without the keyword keeps every member", func(t *testing.T) {
		tree := build(t, "set security zones security-zone Z interfaces [ ge-0/0/0.0 ge-0/0/1.0 ge-0/0/2.0 ]")
		zonesNode := tree.FindChild("security").FindChild("zones")
		if _, _, ok := zoneInterfaceStanzaPackedTail(zonesNode.FindChildren("security-zone")[0].Children[0]); ok {
			t.Fatalf("detector fired on a clean bracket list — it must key on the body keyword, not on nesting")
		}
		secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
		if err := compileZones(zonesNode, secCfg); err != nil {
			t.Fatalf("compileZones: %v", err)
		}
		want := []string{"ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"}
		if got := secCfg.Zones["Z"].Interfaces; !reflect.DeepEqual(got, want) {
			t.Fatalf("control membership = %v, want %v — the loss above must be attributable to the keyword, not to nesting", got, want)
		}
	})
}

// TestZoneInterfaces6735TruncatorLosesTheTrailingMember measures the loss the
// gate exists to prevent, at the compiler level, so the gate is answerable to a
// demonstrated defect rather than a hypothesis. It drives compileZones directly
// (the TOLERANT reading, which still truncates) and asserts that the trailing
// member really does vanish.
//
// If a later change taught the compiler to resolve the ambiguity and keep both
// members, THIS test goes red first and says so — at which point the gate should
// be reconsidered rather than the test amended.
func TestZoneInterfaces6735TruncatorLosesTheTrailingMember(t *testing.T) {
	got, _ := zoneMembership6525(t, `
security {
    zones {
        security-zone Z {
            interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ];
        }
    }
}`)
	want := []string{"ge-0/0/0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compileZones membership = %v, want %v — this test PINS the loss the #6735 gate exists to reject; if the compiler now keeps ge-0/0/1.0 the ambiguity was resolved and the gate needs revisiting, not this assertion",
			got, want)
	}
	// The control: with the keyword removed the same list keeps BOTH members,
	// so the loss above is attributable to the keyword and not to bracket
	// handling in general.
	both, _ := zoneMembership6525(t, `
security {
    zones {
        security-zone Z {
            interfaces [ ge-0/0/0.0 ge-0/0/1.0 ];
        }
    }
}`)
	if wantBoth := []string{"ge-0/0/0.0", "ge-0/0/1.0"}; !reflect.DeepEqual(both, wantBoth) {
		t.Fatalf("control: bracket list without a body keyword compiled %v, want %v", both, wantBoth)
	}
}

// TestZoneInterfaces6735LenientPathWarnsInsteadOfRejecting pins the #1960
// no-brick side: on the tolerant load / peer-sync path the packed-tail gate
// downgrades to a cfg.Warnings entry, so a config an older binary accepted still
// boots — with the loss named rather than silent.
func TestZoneInterfaces6735LenientPathWarnsInsteadOfRejecting(t *testing.T) {
	tree := parseHierarchical(t, zonePackedTailConfig(
		`interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ];`))

	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("premise broken: the strict path must REJECT this stanza, otherwise the lenient assertion below proves nothing")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected a packed-tail stanza: %v — the tolerant path must warn, not brick the boot (#1960)", err)
	}
	var found string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "packed tail") {
			found = w
			break
		}
	}
	if found == "" {
		t.Fatalf("tolerant path emitted no packed-tail warning; warnings=%v — a silent downgrade is the silent loss this gate was written to end (#6735)", cfg.Warnings)
	}
	if !strings.Contains(found, "ge-0/0/1.0") {
		t.Fatalf("packed-tail warning %q does not name the dropped member ge-0/0/1.0", found)
	}
	// Behavior on the tolerant path is unchanged from before the gate: the
	// trailing member is still dropped. The warning is the whole delta.
	if got := cfg.Security.Zones["Z"].Interfaces; !reflect.DeepEqual(got, []string{"ge-0/0/0.0"}) {
		t.Fatalf("tolerant path membership = %v, want [ge-0/0/0.0] — the gate must not change what a leniently-loaded config forwards", got)
	}
}

// TestZoneInterfaces6735FlatSetBracketNestsRatherThanFanning pins the flat-set
// bracket SHAPE, which two comments and docs/config-schema.md previously
// described as "one child per member". It is not: the schema models the
// interface name as a wildcard CONTAINER, so SetPath descends it for the first
// token and then collapses the remainder onto ONE leaf beneath it —
//
//	interfaces            Keys=["interfaces"]  children=1
//	  a                   Keys=["a"]           children=1
//	    b c               Keys=["b","c"]       children=0
//
// zoneInterfaceMembers recurses and reads every key at each level, so the
// members are read correctly and this was a description bug, not a code bug.
// It is worth pinning anyway: the wrong description is exactly the mental model
// that produces a one-level `prop.Children` reader, which is the #6525 defect
// class this whole area exists to close.
func TestZoneInterfaces6735FlatSetBracketNestsRatherThanFanning(t *testing.T) {
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set security zones security-zone Z interfaces [ a b c ]")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	zonesNode := tree.FindChild("security").FindChild("zones")

	var stanza *Node
	for _, inst := range namedInstances(zonesNode.FindChildren("security-zone")) {
		for _, prop := range inst.node.Children {
			if prop.Name() == "interfaces" {
				stanza = prop
			}
		}
	}
	if stanza == nil {
		t.Fatalf("no `interfaces` stanza produced; this test asserted nothing")
	}

	if got := stanza.Keys; !reflect.DeepEqual(got, []string{"interfaces"}) {
		t.Fatalf("stanza Keys = %v, want [interfaces] (`set` never produces the COMPACT shape)", got)
	}
	if len(stanza.Children) != 1 {
		t.Fatalf("stanza has %d children, want exactly 1 — a flat bracket list NESTS, it does not fan out one child per member", len(stanza.Children))
	}
	first := stanza.Children[0]
	if got := first.Keys; !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("first child Keys = %v, want [a]", got)
	}
	if len(first.Children) != 1 {
		t.Fatalf("first child has %d children, want exactly 1 (the collapsed tail leaf)", len(first.Children))
	}
	if got := first.Children[0].Keys; !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Fatalf("tail leaf Keys = %v, want [b c] — the remaining bracket tokens collapse onto ONE leaf", got)
	}

	// The payoff: despite that shape, every member is read. A one-level
	// `prop.Children` reader would return [a] alone.
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(zonesNode, secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	if got, want := secCfg.Zones["Z"].Interfaces, []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("membership = %v, want %v — the recursion must recover every nested member (#5248)", got, want)
	}
}
