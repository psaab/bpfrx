package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #4983: a session now carries the TRUE ingress-interface identity of the
// packet that created it — {IngressIfindex, IngressVlanID}, the binding the
// first frame actually arrived on, stamped once by the dataplane at install.
// Before this, `show security flow session interface <name>` and the matching
// `clear` could only ask "is <name> bound to the session's ingress ZONE?", so
// a session on interface X matched a filter for EVERY sibling interface Y of
// that zone. #4792 widened the zone map to hold every bound interface, which
// is as precise as a zone-derived answer can get; this is the real datum.
//
// The fixtures below use a THREE-interface zone deliberately. A
// single-interface zone makes the assertion true for free — the approximation
// and the fix agree there — so it would prove nothing; and with only two
// interfaces a fix that merely swapped X for "the zone's other interface"
// would still pass. Three lets the assertions distinguish "the one interface
// the session arrived on" from "any other member of its zone".

// zone IDs used across this file.
const (
	ingressIdentityTrustZone   uint16 = 1
	ingressIdentityUntrustZone uint16 = 2
)

// ingressIdentityConfig is a trust zone spanning THREE distinct physical
// interfaces plus a fourth on the untrust side. Two of the trust members are
// VLAN units of ONE trunk NIC (ge-0/0/3.50 and ge-0/0/3.80) — the case the
// ifindex alone cannot separate and the {ifindex, vlan} pair can. This
// mirrors the project's own loss-cluster wiring, where reth0.50 and reth0.80
// share the physical WAN NIC.
func ingressIdentityConfig() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				// Every interface carries `unit 0` — that is how a real
				// Junos config is written (`set interfaces ge-0/0/0 unit 0
				// family inet address ...`) and it is what makes an entry
				// exist in the {ifindex, vlan} name map at all. A unit-less
				// interface produces NO map entry, so a fixture without
				// units would silently fall back for every session and the
				// binding assertions below would pass with the fix reverted.
				"ge-0/0/0": {
					Name:  "ge-0/0/0",
					Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
				},
				"ge-0/0/2": {
					Name:  "ge-0/0/2",
					Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
				},
				"ge-0/0/3": {
					Name: "ge-0/0/3",
					Units: map[int]*config.InterfaceUnit{
						50: {Number: 50, VlanID: 50},
						80: {Number: 80, VlanID: 80},
					},
				},
				"ge-0/0/1": {
					Name:  "ge-0/0/1",
					Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
				},
			},
		},
	}
}

// ingressIdentityIfindex is the injected kernel-ifindex lookup for the
// fixture's netdev names. Values are ordinary small ifindexes of the kind a
// real box hands out; the mapping is the production one
// (buildSessionEgressIfacesWithLookup resolves the PARENT netdev and keys on
// {parent ifindex, unit VLAN}), so the test drives the real name-resolution
// code rather than a hand-rolled table.
func ingressIdentityIfindex(t *testing.T) func(string) (int, error) {
	t.Helper()
	return func(name string) (int, error) {
		switch name {
		case "ge-0-0-0":
			return 11, nil
		case "ge-0-0-1":
			return 12, nil
		case "ge-0-0-2":
			return 13, nil
		case "ge-0-0-3":
			return 14, nil
		default:
			t.Fatalf("unexpected interface lookup %q", name)
			return 0, nil
		}
	}
}

func ingressIdentityFilter(t *testing.T, iface string) *sessionFilter {
	t.Helper()
	cfg := ingressIdentityConfig()
	return &sessionFilter{
		iface: iface,
		zoneIfaces: map[uint16][]string{
			// The trust zone binds THREE interfaces (see the note above).
			ingressIdentityTrustZone:   {"ge-0/0/0", "ge-0/0/2", "ge-0/0/3.50", "ge-0/0/3.80"},
			ingressIdentityUntrustZone: {"ge-0/0/1"},
		},
		ifaceNamesByKey: buildSessionEgressIfacesWithLookup(cfg, ingressIdentityIfindex(t)),
	}
}

// TestMatchesV4IngressIdentityDoesNotMatchSiblingInterface4983 is the
// fail-on-revert binding test. A session that arrived on ge-0/0/0 must match a
// filter for ge-0/0/0 and must NOT match a filter for either sibling
// interface of the same zone.
func TestMatchesV4IngressIdentityDoesNotMatchSiblingInterface4983(t *testing.T) {
	key := dataplane.SessionKey{Protocol: 6}
	// Arrived on ge-0/0/0 (ifindex 11), untagged. No FIB egress result, so the
	// egress arm contributes only the untrust zone's ge-0/0/1 and cannot mask
	// what the ingress arm decides.
	val := dataplane.SessionValue{
		IngressZone:    ingressIdentityTrustZone,
		EgressZone:     ingressIdentityUntrustZone,
		IngressIfindex: 11,
		IngressVlanID:  0,
	}

	if f := ingressIdentityFilter(t, "ge-0/0/0"); !f.matchesV4(key, val) {
		t.Fatal("a session that arrived on ge-0/0/0 must match a filter for ge-0/0/0")
	}

	for _, sibling := range []string{"ge-0/0/2", "ge-0/0/3.50", "ge-0/0/3.80"} {
		f := ingressIdentityFilter(t, sibling)
		if f.matchesV4(key, val) {
			t.Errorf("session arrived on ge-0/0/0 (ifindex 11) but matched a filter for "+
				"sibling interface %q of the SAME zone: the filter is still answering from "+
				"the ingress ZONE instead of the session's recorded ingress identity (#4983)",
				sibling)
		}
	}
}

// TestMatchesV4IngressIdentitySeparatesVLANUnitsOfOneNIC4983 pins the half of
// the identity the ifindex alone cannot carry: ge-0/0/3.50 and ge-0/0/3.80
// share physical ifindex 14, so only the VLAN id distinguishes them.
func TestMatchesV4IngressIdentitySeparatesVLANUnitsOfOneNIC4983(t *testing.T) {
	key := dataplane.SessionKey{Protocol: 6}
	// Arrived on ge-0/0/3.50: physical ifindex 14, VLAN 50.
	val := dataplane.SessionValue{
		IngressZone:    ingressIdentityTrustZone,
		EgressZone:     ingressIdentityUntrustZone,
		IngressIfindex: 14,
		IngressVlanID:  50,
	}

	if f := ingressIdentityFilter(t, "ge-0/0/3.50"); !f.matchesV4(key, val) {
		t.Fatal("a session that arrived on ge-0/0/3.50 must match a filter for ge-0/0/3.50")
	}
	if f := ingressIdentityFilter(t, "ge-0/0/3.80"); f.matchesV4(key, val) {
		t.Error("session arrived on ge-0/0/3.50 but matched a filter for ge-0/0/3.80, the " +
			"OTHER VLAN unit of the same trunk NIC (both are physical ifindex 14, so the " +
			"VLAN half of the ingress identity is what separates them) (#4983)")
	}
	// The parent-interface filter still matches its unit — ifaceMatches'
	// prefix rule is unchanged, and an operator asking for the whole trunk
	// should see traffic on every unit of it.
	if f := ingressIdentityFilter(t, "ge-0/0/3"); !f.matchesV4(key, val) {
		t.Error("a filter for the parent ge-0/0/3 must still match a session on its unit .50")
	}
}

// TestMatchesV6IngressIdentityDoesNotMatchSiblingInterface4983 mirrors the v4
// binding on the IPv6 path, which carries the identical filter arm.
func TestMatchesV6IngressIdentityDoesNotMatchSiblingInterface4983(t *testing.T) {
	key := dataplane.SessionKeyV6{Protocol: 6}
	val := dataplane.SessionValueV6{
		IngressZone:    ingressIdentityTrustZone,
		EgressZone:     ingressIdentityUntrustZone,
		IngressIfindex: 11,
		IngressVlanID:  0,
	}

	if f := ingressIdentityFilter(t, "ge-0/0/0"); !f.matchesV6(key, val) {
		t.Fatal("a v6 session that arrived on ge-0/0/0 must match a filter for ge-0/0/0")
	}
	for _, sibling := range []string{"ge-0/0/2", "ge-0/0/3.50"} {
		f := ingressIdentityFilter(t, sibling)
		if f.matchesV6(key, val) {
			t.Errorf("v6 session arrived on ge-0/0/0 but matched a filter for sibling "+
				"interface %q of the SAME zone (#4983)", sibling)
		}
	}
}

// TestIngressIdentityAbsentFallsBackToZone4983 pins the absent-field branch.
//
// Two sessions live in ONE test and are asserted to be treated DIFFERENTLY: a
// session WITH an ingress identity is matched exactly, and a session WITHOUT
// one (IngressIfindex 0 — the reverse companion, an HA peer-synced session
// whose originating ifindex is node-local and deliberately not carried, or a
// session installed by a pre-#4983 helper mid rolling upgrade) still answers
// from the zone approximation. A test where every session carries the field —
// or none does — cannot see this branch at all.
//
// The two required properties: an absent identity must NOT silently drop the
// session out of `show`/`clear` (0 must not mean "matches nothing"), and it
// must NOT be claimed as an exact match either — it degrades to exactly the
// pre-#4983 zone answer.
func TestIngressIdentityAbsentFallsBackToZone4983(t *testing.T) {
	key := dataplane.SessionKey{Protocol: 6}

	// Same zone, same everything, differing ONLY in whether the ingress
	// identity is carried.
	withIdentity := dataplane.SessionValue{
		IngressZone:    ingressIdentityTrustZone,
		EgressZone:     ingressIdentityUntrustZone,
		IngressIfindex: 11, // arrived on ge-0/0/0
	}
	absentIdentity := dataplane.SessionValue{
		IngressZone: ingressIdentityTrustZone,
		EgressZone:  ingressIdentityUntrustZone,
		// IngressIfindex deliberately 0: no identity carried.
	}

	// A filter for a zone sibling the identified session did NOT arrive on.
	sibling := ingressIdentityFilter(t, "ge-0/0/2")

	if sibling.matchesV4(key, withIdentity) {
		t.Error("the session WITH an ingress identity must not match a zone sibling")
	}
	if !sibling.matchesV4(key, absentIdentity) {
		t.Error("the session WITHOUT an ingress identity must remain reachable through " +
			"the zone approximation: ingress ifindex 0 is not a valid interface and must " +
			"never be read as \"matches nothing\", which would silently hide peer-synced " +
			"and pre-#4983 sessions from show and clear (#4983)")
	}

	// The two sessions must genuinely diverge — if they agreed, the fallback
	// branch would be indistinguishable from the exact branch.
	if sibling.matchesV4(key, withIdentity) == sibling.matchesV4(key, absentIdentity) {
		t.Error("a session with an ingress identity and one without must be treated " +
			"DIFFERENTLY by a zone-sibling filter; identical results mean the fallback " +
			"branch is not being exercised")
	}

	// And 0 must not mean "matches everything" either: an interface bound to
	// NO zone the session touches still must not match it.
	outside := ingressIdentityFilter(t, "ge-0/0/9")
	if outside.matchesV4(key, absentIdentity) {
		t.Error("an absent ingress identity must not match an interface outside both of " +
			"the session's zones: 0 means \"answer from the zone\", not \"matches everything\"")
	}
}

// TestIngressIdentityUnresolvableIfindexFallsBackToZone4983 covers the third
// arm: a NON-ZERO ingress ifindex the running config cannot name (an
// interface deleted since the session was installed, or a tunnel/fabric
// ingress with no config unit). An unnameable identity is not evidence the
// session is uninteresting, so it falls back rather than matching nothing.
func TestIngressIdentityUnresolvableIfindexFallsBackToZone4983(t *testing.T) {
	key := dataplane.SessionKey{Protocol: 6}
	val := dataplane.SessionValue{
		IngressZone:    ingressIdentityTrustZone,
		EgressZone:     ingressIdentityUntrustZone,
		IngressIfindex: 4242, // real identity, no longer nameable from config
	}

	f := ingressIdentityFilter(t, "ge-0/0/2")
	if !f.matchesV4(key, val) {
		t.Error("a session whose non-zero ingress ifindex the config cannot name must " +
			"fall back to the zone approximation, not vanish from show/clear (#4983)")
	}
}

// TestIngressIdentityDoesNotDisturbEgressMatching4983 is the over-reach
// guard. #4983 changes the INGRESS arm only; the egress arm — the FIB
// {ifindex, vlan} result and its zone fallback (#4792/#4650) — must behave
// exactly as before. These assertions stay GREEN with the ingress change
// reverted; that is what makes them a guard rather than a restatement of the
// fix.
func TestIngressIdentityDoesNotDisturbEgressMatching4983(t *testing.T) {
	key := dataplane.SessionKey{Protocol: 6}

	t.Run("egress FIB result still matches its interface", func(t *testing.T) {
		// Ingress identity points at ge-0/0/0 (11); the filter names the
		// EGRESS interface, resolved from the FIB result (12 = ge-0/0/1).
		val := dataplane.SessionValue{
			IngressZone:    ingressIdentityTrustZone,
			EgressZone:     ingressIdentityUntrustZone,
			IngressIfindex: 11,
			FibIfindex:     12,
		}
		if f := ingressIdentityFilter(t, "ge-0/0/1"); !f.matchesV4(key, val) {
			t.Error("a session egressing ge-0/0/1 per its FIB result must still match a " +
				"filter for ge-0/0/1 — the ingress change must not touch the egress arm")
		}
	})

	t.Run("egress zone fallback still matches every bound interface", func(t *testing.T) {
		// No FIB result: the egress arm falls back to every interface bound to
		// the EGRESS zone. Here the egress zone is trust, so a filter for the
		// trust zone's THIRD member must still match via that fallback even
		// though the session's ingress identity names an untrust interface.
		val := dataplane.SessionValue{
			IngressZone:    ingressIdentityUntrustZone,
			EgressZone:     ingressIdentityTrustZone,
			IngressIfindex: 12, // arrived on ge-0/0/1
			FibIfindex:     0,  // no FIB result -> egress zone fallback
		}
		if f := ingressIdentityFilter(t, "ge-0/0/2"); !f.matchesV4(key, val) {
			t.Error("the #4792 egress zone fallback must still match every interface bound " +
				"to the egress zone; the ingress change must not narrow it")
		}
	})

	t.Run("non-interface filters are unaffected", func(t *testing.T) {
		// A protocol filter must still reject a mismatched session regardless
		// of the ingress identity.
		val := dataplane.SessionValue{
			IngressZone:    ingressIdentityTrustZone,
			EgressZone:     ingressIdentityUntrustZone,
			IngressIfindex: 11,
		}
		f := ingressIdentityFilter(t, "ge-0/0/0")
		f.proto = 17 // UDP; the key is TCP
		if f.matchesV4(key, val) {
			t.Error("a protocol mismatch must still reject the session even when the " +
				"ingress interface matches")
		}
	})
}
