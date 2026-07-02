package config

import "testing"

// #3720 (H05): InterfaceHostInboundEffective must fold a physical-interface-level
// override into the effective set for a logical-unit ref, matching the additive
// physical→unit resolution the dataplane enforces. Before the fix the presenter
// read only the exact ref, so `show interfaces <unit>` reported "no override /
// default-deny" while the dataplane admitted the inherited physical override —
// the diagnostic gave the OPPOSITE answer to enforcement. Fail-on-revert.

func hostInboundZone3720() *ZoneConfig {
	return &ZoneConfig{
		Name: "wan",
		// Empty zone-level stanza; enforcement is via the per-interface overrides.
		InterfaceHostInbound: map[string]*HostInboundTraffic{
			"reth0":    {SystemServices: []string{"ping"}},
			"reth0.50": {SystemServices: []string{"ssh"}},
		},
	}
}

// Test_3720_EffectiveUnitUnionsPhysical: the unit ref's effective set is the
// union of the physical-parent override and the unit override.
func Test_3720_EffectiveUnitUnionsPhysical(t *testing.T) {
	z := hostInboundZone3720()
	svc, _, overridden := z.InterfaceHostInboundEffective("reth0.50")
	if !overridden {
		t.Fatal("reth0.50 must report overridden=true (physical + unit override present)")
	}
	if !eqTokens(svc, []string{"ping", "ssh"}) {
		t.Errorf("reth0.50 effective services = %v, want [ping ssh] (physical ping ∪ unit ssh)", svc)
	}
}

// Test_3720_EffectiveUnitInheritsPhysicalOnly: a unit with only a physical-parent
// override still reports the inherited override rather than default-deny.
func Test_3720_EffectiveUnitInheritsPhysicalOnly(t *testing.T) {
	z := hostInboundZone3720()
	svc, _, overridden := z.InterfaceHostInboundEffective("reth0.10")
	if !overridden {
		t.Fatal("reth0.10 must report overridden=true (inherited physical override)")
	}
	if !eqTokens(svc, []string{"ping"}) {
		t.Errorf("reth0.10 effective services = %v, want [ping] (inherited physical)", svc)
	}
}

// Test_3720_EffectivePhysicalRefUnchanged: a bare physical ref resolves to
// zone ∪ its own override, unchanged from before the fix (no parent lookup).
func Test_3720_EffectivePhysicalRefUnchanged(t *testing.T) {
	z := hostInboundZone3720()
	svc, _, overridden := z.InterfaceHostInboundEffective("reth0")
	if !overridden || !eqTokens(svc, []string{"ping"}) {
		t.Errorf("reth0 effective = %v overridden=%v, want [ping] true", svc, overridden)
	}
}

func eqTokens(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
