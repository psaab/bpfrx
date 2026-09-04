package config

import (
	"strings"
	"testing"
)

// #8690. The normalizer's widening rule is: a site may only be normalized once
// the inventory records it as divergent with the elided form compiling to the
// EMPTY stanza, because that is a positive measurement that no reader consumes
// the tail. Until now the rule was checked by hand, per widening.
//
// This binds it. It is the guard that matters most as more families land,
// because the failure it prevents is invisible: normalizing a "partial" site
// truncates a tail that something reads, and the config still commits clean.

// THE RULE, mechanically. No site remaining in the inventory with shape
// "partial" may match a pair the normalizer considers in scope.
//
// This catches the exact mistake family 2 nearly made. `then` looks like a
// scoping keyword — the security-policy `then log` sites are shape "empty" —
// but `policy-options policy-statement <p> term <t> then <action>` is "partial"
// for eight actions. A containerKeyword == "then" rule would have silently
// crossed into them.
func TestNormalizerScopeNeverCoversAPartialSite8690(t *testing.T) {
	shapes := readInventoryShapes(t)
	if len(shapes) == 0 {
		t.Fatal("no inventory shapes; this cell is blind")
	}
	partials := 0
	for site, shape := range shapes {
		if shape != "partial" {
			continue
		}
		partials++
		// Reconstruct the (container keyword, head) pair the normalizer would
		// see: the fold is at the container's last token, and the head is the
		// leaf. Inventory lines are "<container...> <leaf>".
		fields := strings.Fields(site)
		if len(fields) < 2 {
			continue
		}
		head := fields[len(fields)-1]
		kw := fields[len(fields)-2]
		if compactNormalizeInScope(kw, head) {
			t.Errorf("site %q is shape PARTIAL — something consumes part of its tail — but the "+
				"normalizer's scope covers the pair (%q, %q). Truncating it can remove a value "+
				"that is currently read, on a config that commits clean (#8690)", site, kw, head)
		}
	}
	// DEGENERACY CONTROL: if no partial sites remain, the loop above asserts
	// nothing and would pass on any scope whatsoever.
	if partials == 0 {
		t.Fatal("no PARTIAL sites left in the inventory — this cell can no longer catch a scope " +
			"that crosses into one, and its silence means nothing. Re-derive it against whatever " +
			"now distinguishes safe from unsafe sites")
	}
	t.Logf("#8690: %d partial sites checked against the normalizer's scope", partials)
}

// The consequential member of family 2, asserted on the compiled config with a
// positive half. A zone's screen binding decides which IDS profile is applied
// to traffic entering that zone; brace-elided it used to compile to nothing.
func TestElidedZoneScreenBindingReachesTheZone8690(t *testing.T) {
	const braced = `security { screen { ids-option sc1 { icmp { ping-death; } } } zones { security-zone z1 { screen sc1; host-inbound-traffic { system-services ping; } } } }`
	const elided = `security { screen { ids-option sc1 { icmp { ping-death; } } } zones { security-zone z1 screen sc1; } }`
	b, e := compileText(t, braced), compileText(t, elided)
	if b == nil || e == nil {
		t.Fatalf("both spellings must compile (braced=%v elided=%v)", b != nil, e != nil)
	}
	bz, bok := b.Security.Zones["z1"]
	ez, eok := e.Security.Zones["z1"]
	if !bok || !eok {
		t.Fatalf("both spellings must produce the zone; braced=%v elided=%v", bok, eok)
	}
	// POSITIVE HALF: without this the comparison can be between two empty
	// strings and would pass on a compiler that reads neither spelling.
	if bz.ScreenProfile == "" {
		t.Fatal("the braced spelling carried no screen binding — the fixture no longer " +
			"demonstrates the field being read, so the assertion below is vacuous")
	}
	if ez.ScreenProfile != bz.ScreenProfile {
		t.Errorf("the brace-elided screen binding compiled to %q, not %q — the zone applies no "+
			"IDS screen profile on a commit that reported success (#8690)", ez.ScreenProfile, bz.ScreenProfile)
	}
}

// Host-inbound-traffic decides what the box itself accepts on a zone. Same
// shape, different surface, and it is the one an operator is most likely to
// author brace-elided because it reads naturally on one line.
func TestElidedHostInboundTrafficReachesTheZone8690(t *testing.T) {
	const braced = `security { zones { security-zone z1 { host-inbound-traffic { system-services ssh; } } } }`
	const elided = `security { zones { security-zone z1 { host-inbound-traffic system-services ssh; } } }`
	b, e := compileText(t, braced), compileText(t, elided)
	if b == nil || e == nil {
		t.Fatalf("both spellings must compile")
	}
	bz, ez := b.Security.Zones["z1"], e.Security.Zones["z1"]
	if bz == nil || ez == nil {
		t.Fatal("both spellings must produce the zone")
	}
	svc := func(z *ZoneConfig) []string {
		if z.HostInboundTraffic == nil {
			return nil
		}
		return z.HostInboundTraffic.SystemServices
	}
	if len(svc(bz)) == 0 {
		t.Fatal("the braced spelling admitted no system-services — the fixture no longer " +
			"demonstrates the field being read, so the assertion below is vacuous")
	}
	if len(svc(ez)) != len(svc(bz)) {
		t.Errorf("the brace-elided host-inbound-traffic compiled to %v, not %v — the zone admits "+
			"different host services than the operator wrote (#8690)", svc(ez), svc(bz))
	}
}
