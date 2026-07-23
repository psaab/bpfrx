package config

import (
	"reflect"
	"testing"
)

// Tests for #5609: a bracketed / load-override zone membership chain
// `interfaces { a { b; host-inbound-traffic { ... } } }` attached the
// per-interface host-inbound-traffic override to the FIRST member (a) ONLY,
// silently dropping it for every nested member (b), which then fell back to the
// zone-level host-inbound. #5248 already fixed the sibling MEMBERSHIP flatten
// (both a and b become zone members); this completes it so the host-inbound
// override rides the SAME flatten, keeping the two in lockstep.
//
// This shape is reachable only via a raw `load override` block — Junos grammar
// does not let a bracketed `interfaces [ a b ]` list carry a host-inbound-traffic
// body, and the flat-set form is rejected at commit (the collapsed tokens become
// undefined zone members). The hierarchical shape below is the exact AST a load
// override produces.
//
// IMPORTANT (per CLAUDE.md): the hierarchical shape uses parseHierarchical; a
// bracketed flat-set list is built with ParseSetCommand + tree.SetPath.

// TestZoneIfaceHostInboundBracket5609AllMembers is the primary RED-on-revert
// guard: a nested membership chain must attach the per-interface host-inbound
// override to EVERY member. Reverting the fanout to iface.Name()-only leaves
// ge-0/0/1 with no override and this goes RED.
func TestZoneIfaceHostInboundBracket5609AllMembers(t *testing.T) {
	tree := parseHierarchical(t, `
security {
    zones {
        security-zone Z {
            interfaces {
                ge-0/0/0 {
                    ge-0/0/1;
                    host-inbound-traffic {
                        system-services {
                            ssh;
                        }
                        protocols {
                            ospf;
                        }
                    }
                }
            }
        }
    }
}`)
	sec := tree.FindChild("security")
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(sec.FindChild("zones"), secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	z := secCfg.Zones["Z"]

	// Both members must be in the zone (the #5248 membership flatten).
	if !reflect.DeepEqual(z.Interfaces, []string{"ge-0/0/0", "ge-0/0/1"}) {
		t.Fatalf("zone interfaces = %v, want [ge-0/0/0 ge-0/0/1]", z.Interfaces)
	}

	for _, member := range []string{"ge-0/0/0", "ge-0/0/1"} {
		hib := z.InterfaceHostInbound[member]
		if hib == nil {
			t.Fatalf("member %q has no per-interface host-inbound override (bracket fanout dropped it — #5609)", member)
		}
		if !reflect.DeepEqual(hib.SystemServices, []string{"ssh"}) {
			t.Fatalf("member %q system-services = %v, want [ssh]", member, hib.SystemServices)
		}
		if !reflect.DeepEqual(hib.Protocols, []string{"ospf"}) {
			t.Fatalf("member %q protocols = %v, want [ospf]", member, hib.Protocols)
		}
	}
}

// TestZoneIfaceHostInboundBracket5609IndependentCopies pins the aliasing safety:
// each fanned-out member owns its OWN HostInboundTraffic struct, so mutating one
// (as a later mergeHostInbound append+dedup does) never leaks into a sibling.
// Reverting cloneHostInbound makes the two members share one pointer and this
// goes RED.
func TestZoneIfaceHostInboundBracket5609IndependentCopies(t *testing.T) {
	tree := parseHierarchical(t, `
security {
    zones {
        security-zone Z {
            interfaces {
                ge-0/0/0 {
                    ge-0/0/1;
                    host-inbound-traffic {
                        system-services {
                            ssh;
                        }
                    }
                }
            }
        }
    }
}`)
	sec := tree.FindChild("security")
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(sec.FindChild("zones"), secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	z := secCfg.Zones["Z"]
	a := z.InterfaceHostInbound["ge-0/0/0"]
	b := z.InterfaceHostInbound["ge-0/0/1"]
	if a == nil || b == nil {
		t.Fatalf("missing override: a=%v b=%v", a, b)
	}
	if a == b {
		t.Fatalf("members alias the same *HostInboundTraffic; want independent copies (#5609)")
	}
	// Mutate a's slice in place; b must be unaffected.
	a.SystemServices = append(a.SystemServices, "ping")
	if reflect.DeepEqual(b.SystemServices, a.SystemServices) {
		t.Fatalf("mutating ge-0/0/0 override leaked into ge-0/0/1: b=%v (aliasing — #5609)", b.SystemServices)
	}
	if !reflect.DeepEqual(b.SystemServices, []string{"ssh"}) {
		t.Fatalf("ge-0/0/1 system-services = %v, want [ssh] (unmutated)", b.SystemServices)
	}
}

// TestZoneIfaceHostInboundBracket5609NoCrossContamination is the negative
// control: the NORMAL one-interface-per-child shape (each interface its own
// child with its own host-inbound) keeps DISTINCT overrides — the fanout must
// not spread one interface's override onto another. This stays byte-identical to
// the pre-#5609 behavior; it fails only if the fanout wrongly widens the member
// set for a plain single-interface node.
func TestZoneIfaceHostInboundBracket5609NoCrossContamination(t *testing.T) {
	tree := parseHierarchical(t, `
security {
    zones {
        security-zone Z {
            interfaces {
                ge-0/0/0 {
                    host-inbound-traffic {
                        system-services {
                            ssh;
                        }
                    }
                }
                ge-0/0/1 {
                    host-inbound-traffic {
                        system-services {
                            ping;
                        }
                    }
                }
            }
        }
    }
}`)
	sec := tree.FindChild("security")
	secCfg := &SecurityConfig{Zones: map[string]*ZoneConfig{}}
	if err := compileZones(sec.FindChild("zones"), secCfg); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
	z := secCfg.Zones["Z"]
	if got := z.InterfaceHostInbound["ge-0/0/0"]; got == nil || !reflect.DeepEqual(got.SystemServices, []string{"ssh"}) {
		t.Fatalf("ge-0/0/0 override = %+v, want system-services [ssh]", got)
	}
	if got := z.InterfaceHostInbound["ge-0/0/1"]; got == nil || !reflect.DeepEqual(got.SystemServices, []string{"ping"}) {
		t.Fatalf("ge-0/0/1 override = %+v, want system-services [ping]", got)
	}
	if len(z.InterfaceHostInbound) != 2 {
		t.Fatalf("InterfaceHostInbound has %d entries, want exactly 2 (no phantom members)", len(z.InterfaceHostInbound))
	}
}
