package config

import (
	"reflect"
	"sort"
	"testing"
)

// Tests for #6391: a per-interface `host-inbound-traffic` override authored
// under ONE member of a bracketed / shared-container interface membership must
// NOT leak onto the sibling members that merely share the bracket.
//
// Background. #5248 flattens the bracketed `interfaces [ a b c ]` membership so
// every member lands in `zone.Interfaces` (a security-boundary fix). SetPath
// nests the bracket tail under the first member — `interfaces -> a(container) ->
// b(leaf)` — so a subsequent `interfaces a host-inbound-traffic { ... }` reuses
// the SAME `a` container and the host-inbound body becomes a child of the node
// that also carries the `b` membership leaf.
//
// PR #6389 (advances #5609, CLOSED unmerged) tried to make a hierarchical
// multi-member `load override` block apply the override to every member by
// fanning the parsed host-inbound across `zoneInterfaceMembers(iface)`. That
// fanout is UNSOUND: the flat-set single-scoped case and the hierarchical
// multi-member case compile to the SAME AST, so the fanout cannot tell them
// apart and OVER-ADMITS — it opens the service on `b` for the common
//
//	set security zones security-zone Z interfaces [ a b ]
//	set security zones security-zone Z interfaces a host-inbound-traffic system-services ssh
//
// config that scopes ssh to `a` only. Codex's hostile review of #6389 plus a
// firsthand repro caught this host-inbound sibling leak; #6389 closed unmerged.
//
// Current master is the fail-SAFE status quo: `compileZones` keys the
// per-interface override strictly on `iface.Name()` (the direct child the
// stanza was written under), so a sibling never inherits it. These tests are
// the RED-on-revert guard that PINS that isolation: re-introducing the #6389
// `for _, member := range zoneInterfaceMembers(iface)` fanout turns the
// CONTAINER-SHARING cases RED (a sibling wrongly carries the override) —
// first-member, three-member, multi-service, protocols, and the two
// hierarchical multi-member-body cases. The later-member and
// no-shared-backing-store cases stay GREEN CONTROLS: their interfaces do NOT
// share a SetPath container (SetPath splits a later-authored member, and two
// separately-authored top-level interfaces are independent), so the fanout does
// not touch them — they prove the guard is not a tautology. The guard advances
// #6391 in the issue's option-1 (fail-safe) direction; see docs/config-schema.md.
//
// TWO KINDS of assertion below, do NOT conflate them:
//
//   - FLAT-SET, INDIVIDUALLY-SCOPED (the first/later-member, three-member,
//     multi-service and protocols cases, plus the aliasing guard): a service or
//     protocol authored under ONE named interface via its OWN `set` statement
//     (`interfaces a host-inbound-traffic system-services ssh`) must never
//     appear on a sibling. This is UNCONDITIONALLY correct under every design
//     option (1/2/3) — an individually-authored per-interface stanza is
//     single-scoped by definition, so a future parse-time fan (option 2/3) for
//     the multi-member case must still leave these untouched. Asserted firmly.
//
//   - MULTI-MEMBER BODY (the two hierarchical cases): a host-inbound BODY
//     hanging off a bracket-membership / shared container
//     (`[ a b ] { host-inbound ... }` or the `a { b; host-inbound ... }`
//     load-override artifact). First-member-only here is the CURRENT option-1
//     fail-safe outcome, NOT the final multi-member semantics: options 2/3
//     (parse-time scope disambiguation, still an open DESIGN call on #6391) may
//     deliberately fan the body to every member. These two cases pin CURRENT
//     behavior and catch UNINTENDED drift; when option 2/3 lands, its author
//     updates these two expectations as part of that work. They must NOT be
//     read as asserting that first-member-only is correct forever.
//
// IMPORTANT (per CLAUDE.md): flat-set syntax is built with ParseSetCommand +
// tree.SetPath, never NewParser; the hierarchical shape uses parseHierarchical.

// hib6391 is a normalized (sorted) view of one compiled per-interface
// HostInboundTraffic that captures BOTH admission dimensions — system-services
// AND protocols. Comparing the full struct (not just system-services) means a
// #6389-style fanout that leaked only host-inbound `protocols` (ospf/bgp/...) to
// a sibling is caught too, not just a system-services leak.
type hib6391 struct {
	SystemServices []string
	Protocols      []string
}

// compileHostInbound6391 compiles the zones subtree and returns the FULL
// per-interface host-inbound map: every key present in InterfaceHostInbound
// (an interface with no override is simply absent), each mapped to its sorted
// system-services + protocols. Returning the whole map — every key, both
// dimensions — is what makes the sibling-leak assertion airtight: an extra
// sibling key, or an extra service/protocol on any interface, fails the
// DeepEqual.
func compileHostInbound6391(t *testing.T, tree *ConfigTree) map[string]hib6391 {
	t.Helper()
	sec := tree.FindChild("security")
	if sec == nil {
		t.Fatalf("no security node in tree")
	}
	zonesNode := sec.FindChild("zones")
	if zonesNode == nil {
		t.Fatalf("no security zones node in tree")
	}
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(zonesNode, secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	out := map[string]hib6391{}
	for _, z := range secCfg.Zones {
		for ifName, hib := range z.InterfaceHostInbound {
			// Include EVERY key, even a (defensive) nil value, so an
			// unexpected sibling key fails the assertion regardless of its
			// contents. sort.Strings(nil) is a no-op and append([]string(nil),
			// nil...) stays nil, so an absent dimension normalizes to nil and
			// matches an unset field in the expected literal.
			v := hib6391{}
			if hib != nil {
				v.SystemServices = append([]string(nil), hib.SystemServices...)
				v.Protocols = append([]string(nil), hib.Protocols...)
				sort.Strings(v.SystemServices)
				sort.Strings(v.Protocols)
			}
			out[ifName] = v
		}
	}
	return out
}

func compileHostInbound6391FromSet(t *testing.T, cmds ...string) map[string]hib6391 {
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
	return compileHostInbound6391(t, tree)
}

// assertHostInbound6391 asserts the compiled per-interface host-inbound map is
// EXACTLY want — every key and both admission dimensions. Using the full map
// (not a spot check on one interface) makes the sibling-leak assertion airtight:
// an extra sibling key, or an extra service/protocol anywhere, is a failure.
func assertHostInbound6391(t *testing.T, got, want map[string]hib6391) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("per-interface host-inbound = %+v, want %+v (sibling leak?)", got, want)
	}
}

// TestHostInbound6391FlatSetFirstMemberNoSiblingLeak is the primary RED-on-revert
// guard and the exact issue repro: a two-member bracket with a host-inbound
// override written under the FIRST member via its own `set` statement must scope
// the service to that member ONLY. This is an UNCONDITIONAL invariant — an
// individually-authored per-interface stanza stays single-scoped under every
// design option (1/2/3). The #6389 fanout opens ssh on the sibling ge-0/0/1 →
// this goes RED.
func TestHostInbound6391FlatSetFirstMemberNoSiblingLeak(t *testing.T) {
	got := compileHostInbound6391FromSet(t,
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
	)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391FlatSetLaterMemberNoSiblingLeak covers the symmetric
// ordering: the override written under a LATER bracket member scopes to that
// member only, and the first member stays clean. In this ordering SetPath
// splits ge-0/0/1 into its own top-level container, so the direct-child keying
// is already correct — the case pins that the fix does not regress it.
func TestHostInbound6391FlatSetLaterMemberNoSiblingLeak(t *testing.T) {
	got := compileHostInbound6391FromSet(t,
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
		"set security zones security-zone trust interfaces ge-0/0/1 host-inbound-traffic system-services ssh",
	)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/1": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391ThreeMemberNoSiblingLeak proves the override does not reach
// ANY sibling, not just the adjacent one: a 3-member bracket with the override
// under the first member must leave BOTH later members clean. The #6389 fanout
// leaks onto ge-0/0/1 AND ge-0/0/2 → RED.
func TestHostInbound6391ThreeMemberNoSiblingLeak(t *testing.T) {
	got := compileHostInbound6391FromSet(t,
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ge-0/0/2 ]",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
	)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391MultiServiceNoSiblingLeak proves no cross-SERVICE leak: two
// services (ssh AND ping) under the first member must both scope to that member
// only — the sibling gets neither.
func TestHostInbound6391MultiServiceNoSiblingLeak(t *testing.T) {
	got := compileHostInbound6391FromSet(t,
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ping",
	)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ping", "ssh"}},
	})
}

// TestHostInbound6391ProtocolsNoSiblingLeak exercises the PROTOCOLS admission
// dimension (not just system-services): an override under the FIRST member
// carrying BOTH a system-service (ssh) and a protocol (ospf) must scope both to
// that member — the sibling gets neither. Without a Protocols case the guard's
// full-map assertion never observes a protocols leak; the #6389 fanout leaks
// ospf onto ge-0/0/1 too → RED. Individually-scoped, so an UNCONDITIONAL
// invariant under every design option.
func TestHostInbound6391ProtocolsNoSiblingLeak(t *testing.T) {
	got := compileHostInbound6391FromSet(t,
		"set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic protocols ospf",
	)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}, Protocols: []string{"ospf"}},
	})
}

// TestHostInbound6391HierarchicalNestedChildNoSiblingLeak covers the exact
// load-override AST shape #6389 targeted: a hierarchical block that NESTS the
// second member under the first alongside a host-inbound body
// (`interfaces { ge-0/0/0 { ge-0/0/1; host-inbound-traffic { ssh } } }`). This
// is a MULTI-MEMBER BODY case, NOT an individually-scoped stanza: first-member-
// only (ssh on ge-0/0/0, nested ge-0/0/1 clean) is the CURRENT option-1 fail-
// safe outcome, not the final multi-member semantics. An options-2/3 design fix
// (parse-time scope disambiguation, still open on #6391) may deliberately fan
// the body to ge-0/0/1 too; when it lands, update this expectation. Today the
// assertion pins current behavior and the #6389 fanout (which opens ssh on
// ge-0/0/1 without that design work) turns it RED.
func TestHostInbound6391HierarchicalNestedChildNoSiblingLeak(t *testing.T) {
	tree := parseHierarchical(t, `
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0 {
                    ge-0/0/1;
                    host-inbound-traffic { system-services ssh; }
                }
            }
        }
    }
}`)
	got := compileHostInbound6391(t, tree)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391HierarchicalBracketBodyNoSiblingLeak covers the
// Keys=[a,b] hierarchical bracket-with-body shape
// (`interfaces { [ ge-0/0/0 ge-0/0/1 ] { host-inbound-traffic { ssh } } }`) —
// the canonical MULTI-MEMBER BODY: a host-inbound stanza authored ON the bracket
// membership itself. The lexer strips the brackets so the member node carries
// both names in its Keys; iface.Name() is the first key, so the CURRENT option-1
// fail-safe scopes ssh to ge-0/0/0 and leaves ge-0/0/1 clean. This is the
// under-application #5609-A3.1 / #6391 tracks: first-member-only is the fail-safe
// default PENDING the options-2/3 design call, NOT the final semantics — an
// option-2/3 fix that fans the body to every bracket member will intentionally
// flip this expectation. It is asserted here to pin current behavior, not to
// declare first-member-only correct forever.
func TestHostInbound6391HierarchicalBracketBodyNoSiblingLeak(t *testing.T) {
	tree := parseHierarchical(t, `
security {
    zones {
        security-zone trust {
            interfaces {
                [ ge-0/0/0 ge-0/0/1 ] {
                    host-inbound-traffic { system-services ssh; }
                }
            }
        }
    }
}`)
	got := compileHostInbound6391(t, tree)
	assertHostInbound6391(t, got, map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
	})
}

// TestHostInbound6391NoSharedBackingStoreAcrossInterfaces guards the aliasing
// trap the #6389 review flagged: distinct per-interface overrides must not share
// a mutable backing slice. Two interfaces each authored with a DIFFERENT service
// must keep independent SystemServices — appending to one (as a later
// mergeHostInbound would) must never surface in the other. Assert the WHOLE
// compiled map (cardinality + both dimensions per interface) AND pointer
// independence of the backing arrays.
func TestHostInbound6391NoSharedBackingStoreAcrossInterfaces(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/1 host-inbound-traffic system-services ping",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	// Full-map cardinality: EXACTLY the two authored interfaces, each with its
	// own single service and no protocols. An extra sibling key (or a leaked
	// service/protocol) fails here.
	assertHostInbound6391(t, compileHostInbound6391(t, tree), map[string]hib6391{
		"ge-0/0/0": {SystemServices: []string{"ssh"}},
		"ge-0/0/1": {SystemServices: []string{"ping"}},
	})
	sec := tree.FindChild("security")
	zonesNode := sec.FindChild("zones")
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(zonesNode, secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	zone := secCfg.Zones["trust"]
	a := zone.InterfaceHostInbound["ge-0/0/0"]
	b := zone.InterfaceHostInbound["ge-0/0/1"]
	if a == nil || b == nil {
		t.Fatalf("expected both interfaces to carry a host-inbound override, got a=%v b=%v", a, b)
	}
	if !reflect.DeepEqual(a.SystemServices, []string{"ssh"}) {
		t.Fatalf("ge-0/0/0 system-services = %v, want [ssh]", a.SystemServices)
	}
	if !reflect.DeepEqual(b.SystemServices, []string{"ping"}) {
		t.Fatalf("ge-0/0/1 system-services = %v, want [ping]", b.SystemServices)
	}
	// Mutating one must not disturb the other (independent backing arrays).
	a.SystemServices = append(a.SystemServices, "https")
	if len(b.SystemServices) != 1 || b.SystemServices[0] != "ping" {
		t.Fatalf("aliasing: mutating ge-0/0/0 leaked into ge-0/0/1: %v", b.SystemServices)
	}
}
