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
	// ADMISSION COMES FROM THE PASS, NOT FROM A RE-DERIVED MODEL OF IT (#8690).
	//
	// This loop used to reconstruct the pair from the inventory path —
	// `head := fields[len(fields)-1]; kw := fields[len(fields)-2]` — and ask
	// `compactNormalizeInScope(kw, head)`. That is the same re-derivation the
	// scope guard in compact_normalize_scope_8690_test.go documents as WRONG,
	// applied to the more dangerous half of the rule.
	//
	// Production calls the predicate with `node.Keys[0]`, which is:
	//
	//	wildcard container   `interfaces { ge-0-0-0 mtu 1500; }`  -> ("ge-0-0-0", "mtu")  the INSTANCE NAME
	//	named child w/ args  `system { login { user u1 class X; } }` -> ("user", "class") the KEYWORD
	//	plain child          `term t1 { then metric 5; }`         -> ("then", "metric")   the keyword
	//
	// The inventory path carries the schema ARG PLACEHOLDER in that position,
	// so for the ten `interfaces xpfname <leaf>` / `bridge-domains xpfname
	// <leaf>` partials this cell asked ("xpfname", …) while production asks
	// (<instance name>, …). It happened to be SOUND — production's keyword
	// there is an arbitrary instance name no static rule can match, and a
	// head-only rule matches both spellings — but sound BY ACCIDENT, not by
	// construction.
	//
	// It goes blind the moment a partial site appears under a named-child-with-
	// args container: production would ask ("user", "uid") while this cell asks
	// ("xpfarg", "uid"), match nothing, and report a clean scope for a widening
	// that truncates a tail something reads. That is not hypothetical — `system
	// login user <u> uid` became a live site during #8697, and the identical
	// ("user", "class") shape already caused a real miss in #8708.
	//
	// So ask the pass. Build the elided spelling, run it, and require that the
	// pass leave the site ALONE. No model, no drift, and the answer is
	// production's own.
	partials := 0
	examined := 0
	byKey := map[string]bool{}
	for site, shape := range shapes {
		if shape == "partial" {
			partials++
			byKey[site] = true
		}
	}
	for _, s := range collectCompactSites() {
		if len(s.container) == 0 || strings.HasPrefix(s.container[0], "groups") {
			continue
		}
		siteKey := strings.Join(s.container, " ") + " " + s.leaf
		if !byKey[siteKey] {
			continue
		}
		parent := s.container[:len(s.container)-1]
		stanza := s.container[len(s.container)-1]
		// #9056: a VALUELESS FLAG site has no value to vary, so synthPair
		// refuses it and the site would be SKIPPED -- which the reconciliation
		// below correctly reports as UNCHECKED rather than safe. Five of the
		// sixteen partial sites are flags (`interfaces <if> disable`,
		// `vlan-tagging`, `flexible-vlan-tagging`, `gratuitous-arp-reply`,
		// `no-gratuitous-arp-request`), so without this branch the guard covers
		// 11 of 16 and says so.
		//
		// The elided spelling of a flag is the leaf alone; appending an empty
		// value would spell `... disable ;`, which is not the operator's line.
		elided := ""
		if s.flag {
			elided = nest(parent, contextFor(parent)+stanza+" "+s.leaf+";")
		} else {
			v1, _, ok := synthPair(s.node)
			if !ok {
				continue
			}
			elided = nest(parent, contextFor(parent)+stanza+" "+s.leaf+" "+v1+";")
		}
		probe, perrs := NewParser(elided).Parse()
		if len(perrs) > 0 || probe == nil {
			continue
		}
		examined++
		if normalizeCompactStanzas(probe) != 0 {
			t.Errorf("site %q is shape PARTIAL — something consumes part of its tail — but the "+
				"normalizer TOUCHES it. Truncating it can remove a value that is currently "+
				"read, on a config that commits clean (#8690)", siteKey)
		}
	}
	// DEGENERACY CONTROL, in two parts.
	//
	// The first is the original: with no partial sites left the loop asserts
	// nothing and would pass against any scope whatsoever.
	if partials == 0 {
		t.Fatal("no PARTIAL sites left in the inventory — this cell can no longer catch a scope " +
			"that crosses into one, and its silence means nothing. Re-derive it against whatever " +
			"now distinguishes safe from unsafe sites")
	}
	// The second is NEW and is the one the re-derivation made necessary: this
	// loop can now SKIP a partial site (unsynthesizable value, unparseable
	// spelling, absent from the census walk) and a skip is silent. A site this
	// cell did not examine is not a site it found safe, so the count must
	// reconcile against the inventory rather than being reported as-is.
	if examined != partials {
		t.Errorf("examined %d of %d PARTIAL sites — %d were skipped and are therefore "+
			"UNCHECKED, not safe. A partial site the guard cannot reach is exactly "+
			"the one a widening can cross into unobserved (#8690)", examined, partials, partials-examined)
	}
	t.Logf("#8690: %d of %d PARTIAL sites driven through the real pass", examined, partials)
}

// The consequential member of family 2, asserted on the compiled config with a
// positive half.
//
// OBSERVATION BOUNDARY: this reads `ZoneConfig.ScreenProfile`. That a zone's
// screen binding decides which IDS profile is applied to traffic entering the
// zone is evidence about what the field MEANS, checked by reading the
// consumers — it is not something this assertion can see. A guard that names a
// mechanism while observing only an outcome passes for the wrong reason the
// moment that mechanism moves.
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
