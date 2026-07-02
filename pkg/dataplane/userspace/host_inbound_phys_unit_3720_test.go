package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3720: the per-interface host-inbound override resolution
// (buildInterfaceHostInboundMap) must UNION a physical-interface-level override
// with a more-specific unit-level override, not let the sorted-first physical
// ref shadow the unit (the first-writer-wins bug). These are fail-on-revert:
// restore the old `if _, ok := out[key]; !ok` skip and the union assertions go
// RED. Single-level (physical-only / unit-only) resolution is unchanged.

// hostInboundCfg3720 declares a physical override (ping) on reth0 and a unit
// override (ssh) on reth0.50 in the SAME zone, with an empty zone-level stanza.
// reth0.10 carries only the inherited physical override.
func hostInboundCfg3720() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			10: {Number: 10, Addresses: []string{"10.0.10.1/24"}},
			50: {Number: 50, Addresses: []string{"10.0.50.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:       "wan",
			Interfaces: []string{"reth0", "reth0.50"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0":    {SystemServices: []string{"ping"}},
				"reth0.50": {SystemServices: []string{"ssh"}},
			},
		},
	}
	return cfg
}

// Test_3720_UnitOverrideUnionsWithPhysical is the core fail-on-revert: the unit
// override (ssh) must UNION with the inherited physical override (ping), so
// reth0.50 admits BOTH. Before the fix the physical ref sorted first and filled
// out["reth0.50"], so the exact unit override was dropped and reth0.50 admitted
// only ping.
func Test_3720_UnitOverrideUnionsWithPhysical(t *testing.T) {
	m := buildInterfaceHostInboundMap(hostInboundCfg3720())

	got := m["reth0.50"]
	if got == nil {
		t.Fatal("reth0.50 must carry an effective override (physical ∪ unit)")
	}
	if !eqStr(got.SystemServices, []string{"ping", "ssh"}) {
		t.Errorf("reth0.50 effective services = %v, want [ping ssh] (physical ping ∪ unit ssh)", got.SystemServices)
	}

	// A unit with ONLY the inherited physical override is unchanged (single-level).
	if inh := m["reth0.10"]; inh == nil || !eqStr(inh.SystemServices, []string{"ping"}) {
		t.Errorf("reth0.10 inherited services = %v, want [ping] (physical only)", inh)
	}

	// The bare physical key itself still resolves to the physical override.
	if phys := m["reth0"]; phys == nil || !eqStr(phys.SystemServices, []string{"ping"}) {
		t.Errorf("reth0 (bare) services = %v, want [ping]", phys)
	}
}

// Test_3720_ViewScopesUnionedOverride is the end-to-end fail-on-revert through
// BuildZoneHostInboundViews: reth0.50's address lands in a view whose effective
// set is the union {ping, ssh}, while reth0.10's address lands in the
// physical-only {ping} view.
func Test_3720_ViewScopesUnionedOverride(t *testing.T) {
	views := BuildZoneHostInboundViews(hostInboundCfg3720())
	byAddr := map[string][]string{}
	for _, v := range views {
		for _, a := range v.V4Addrs {
			byAddr[a] = v.SystemServices
		}
	}
	if !eqStr(byAddr["10.0.50.1"], []string{"ping", "ssh"}) {
		t.Errorf("reth0.50 address effective services = %v, want [ping ssh]", byAddr["10.0.50.1"])
	}
	if !eqStr(byAddr["10.0.10.1"], []string{"ping"}) {
		t.Errorf("reth0.10 address effective services = %v, want [ping]", byAddr["10.0.10.1"])
	}
}

// Test_3720_M01_PhysicalOverrideNoCrossZoneLeak: a physical override authored in
// zone trust must NOT expand onto a unit (reth0.20) that resolves to a DIFFERENT
// zone (guest). Before the fix the physical override leaked onto every unit of
// the physical interface regardless of the unit's resolved zone.
func Test_3720_M01_PhysicalOverrideNoCrossZoneLeak(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			10: {Number: 10, Addresses: []string{"10.0.10.1/24"}},
			20: {Number: 20, Addresses: []string{"10.0.20.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		// trust claims the bare physical (and so every unit not otherwise owned)
		// and authors a physical override.
		"trust": {
			Name:       "trust",
			Interfaces: []string{"reth0"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0": {SystemServices: []string{"ping"}},
			},
		},
		// guest owns reth0.20 explicitly — a different zone.
		"guest": {Name: "guest", Interfaces: []string{"reth0.20"}},
	}

	m := buildInterfaceHostInboundMap(cfg)
	if ov := m["reth0.20"]; ov != nil {
		t.Errorf("reth0.20 (owned by guest) must NOT inherit trust's physical override, got %v", ov.SystemServices)
	}
	// reth0.10 is owned by trust and must inherit the physical override.
	if ov := m["reth0.10"]; ov == nil || !eqStr(ov.SystemServices, []string{"ping"}) {
		t.Errorf("reth0.10 (owned by trust) effective = %v, want [ping]", ov)
	}
}
