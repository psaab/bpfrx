package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5489: cross-zone host-inbound admission bleed on the EXACT-UNIT branch of
// buildInterfaceHostInboundMap. The physical-expansion branch already carries a
// #3720 cross-zone quarantine (`zoneByIface[un] != zn`), but the logical-unit
// branch (`strings.Contains(ref, ".")`) unconditionally UNIONed the override for
// EVERY zone that named the unit. On a tolerated duplicate ownership (a lenient
// `load override` / peer-sync retaining two zones both claiming the same
// reth0.100), buildInterfaceZoneMap resolves the OWNER as the first sorted zone,
// but the override loop visited BOTH zones and merged each into out[ref], so the
// winning zone's InterfaceSnapshot / ZoneHostInboundView received the UNION —
// including the LOSING zone's admission tokens (e.g. SSH). These tests are
// fail-on-revert: drop the exact-unit guard and the losing zone's ssh bleeds
// into the owner's effective set and the assertions go RED.

// hostInboundCfg5489 declares TWO zones both claiming reth0.100. The owner
// (first sorted: "azone-owner") authors a unit override admitting ONLY ping. The
// loser ("zzone-loser") authors a unit override admitting ssh that the owner
// lacks. Neither zone declares a zone-level host-inbound stanza, so the
// effective set is exactly the resolved per-interface override.
func hostInboundCfg5489() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			100: {Number: 100, Addresses: []string{"10.0.100.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"azone-owner": {
			Name:       "azone-owner",
			Interfaces: []string{"reth0.100"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0.100": {SystemServices: []string{"ping"}},
			},
		},
		"zzone-loser": {
			Name:       "zzone-loser",
			Interfaces: []string{"reth0.100"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0.100": {SystemServices: []string{"ssh"}},
			},
		},
	}
	return cfg
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// Test_5489_OwnerZonePicksFirstSorted confirms the ownership premise: on a
// duplicate-ownership config, buildInterfaceZoneMap resolves the unit's owner to
// the first sorted zone, and the loser is NOT the owner.
func Test_5489_OwnerZonePicksFirstSorted(t *testing.T) {
	z := buildInterfaceZoneMap(hostInboundCfg5489())
	if got := z["reth0.100"]; got != "azone-owner" {
		t.Fatalf("buildInterfaceZoneMap owner of reth0.100 = %q, want azone-owner (first sorted)", got)
	}
}

// Test_5489_ExactUnitNoCrossZoneLeak is the core fail-on-revert: the resolved
// override for reth0.100 must carry ONLY the owner zone's tokens ([ping]) — the
// losing zone's ssh admission must NOT bleed into out[ref]. Revert the exact-unit
// guard and out["reth0.100"] becomes [ping ssh] (the union) and this goes RED.
func Test_5489_ExactUnitNoCrossZoneLeak(t *testing.T) {
	m := buildInterfaceHostInboundMap(hostInboundCfg5489())

	ov := m["reth0.100"]
	if ov == nil {
		t.Fatal("reth0.100 must carry the owner zone's effective override")
	}
	if containsStr(ov.SystemServices, "ssh") {
		t.Errorf("reth0.100 effective services = %v: losing zone's ssh admission bled into the owner's view (#5489)", ov.SystemServices)
	}
	if !eqStr(ov.SystemServices, []string{"ping"}) {
		t.Errorf("reth0.100 effective services = %v, want [ping] (owner-only, no cross-zone union)", ov.SystemServices)
	}
}

// Test_5489_SnapshotNoCrossZoneLeak is the end-to-end fail-on-revert through the
// InterfaceSnapshot stamping path (buildInterfaceSnapshots): the reth0.100
// snapshot is stamped from its OWNER zone, so its effective host-inbound set must
// be [ping] with no ssh from the losing zone.
func Test_5489_SnapshotNoCrossZoneLeak(t *testing.T) {
	snaps := buildInterfaceSnapshots(hostInboundCfg5489())
	var found bool
	for _, s := range snaps {
		if s.Name != "reth0.100" {
			continue
		}
		found = true
		if s.Zone != "azone-owner" {
			t.Errorf("reth0.100 snapshot Zone = %q, want azone-owner (owner)", s.Zone)
		}
		if !s.HostInboundConfigured {
			t.Errorf("reth0.100 snapshot must mark HostInboundConfigured")
		}
		if containsStr(s.HostInboundSystemServices, "ssh") {
			t.Errorf("reth0.100 snapshot services = %v: losing zone's ssh bled in (#5489)", s.HostInboundSystemServices)
		}
		if !eqStr(s.HostInboundSystemServices, []string{"ping"}) {
			t.Errorf("reth0.100 snapshot services = %v, want [ping]", s.HostInboundSystemServices)
		}
	}
	if !found {
		t.Fatal("no InterfaceSnapshot emitted for reth0.100")
	}
}

// Test_5489_ViewNoCrossZoneLeak is the end-to-end fail-on-revert through
// BuildZoneHostInboundViews: reth0.100's address lands in the owner zone's view
// whose effective set is [ping], never the losing zone's ssh.
func Test_5489_ViewNoCrossZoneLeak(t *testing.T) {
	views := BuildZoneHostInboundViews(hostInboundCfg5489())
	byAddr := map[string][]string{}
	zoneByAddr := map[string]string{}
	for _, v := range views {
		for _, a := range v.V4Addrs {
			byAddr[a] = v.SystemServices
			zoneByAddr[a] = v.Zone
		}
	}
	if z := zoneByAddr["10.0.100.1"]; z != "azone-owner" {
		t.Errorf("reth0.100 address scoped to zone %q, want azone-owner", z)
	}
	if containsStr(byAddr["10.0.100.1"], "ssh") {
		t.Errorf("reth0.100 view services = %v: losing zone's ssh bled into the owner's view (#5489)", byAddr["10.0.100.1"])
	}
	if !eqStr(byAddr["10.0.100.1"], []string{"ping"}) {
		t.Errorf("reth0.100 view services = %v, want [ping]", byAddr["10.0.100.1"])
	}
}

// Test_5489_SingleOwnerUnaffected proves the guard preserves the non-conflict
// (single-owner) case bit-for-bit: when exactly ONE zone owns reth0.100, its own
// unit override is applied normally (the guard's `z == zn` path is a no-op skip).
func Test_5489_SingleOwnerUnaffected(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			100: {Number: 100, Addresses: []string{"10.0.100.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:       "trust",
			Interfaces: []string{"reth0.100"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0.100": {SystemServices: []string{"ssh"}},
			},
		},
	}
	m := buildInterfaceHostInboundMap(cfg)
	if ov := m["reth0.100"]; ov == nil || !eqStr(ov.SystemServices, []string{"ssh"}) {
		t.Errorf("single-owner reth0.100 effective = %v, want [ssh] (own override applied)", ov)
	}
}

// Test_5489_PhysicalBranchGuardStillHolds re-asserts the pre-existing #3720
// physical-expansion quarantine survives alongside the new exact-unit guard: a
// physical override in trust must not leak onto reth0.20 owned by guest, while
// reth0.10 owned by trust still inherits it.
func Test_5489_PhysicalBranchGuardStillHolds(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			10: {Number: 10, Addresses: []string{"10.0.10.1/24"}},
			20: {Number: 20, Addresses: []string{"10.0.20.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:       "trust",
			Interfaces: []string{"reth0"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"reth0": {SystemServices: []string{"ping"}},
			},
		},
		"guest": {Name: "guest", Interfaces: []string{"reth0.20"}},
	}
	m := buildInterfaceHostInboundMap(cfg)
	if ov := m["reth0.20"]; ov != nil {
		t.Errorf("reth0.20 (owned by guest) must NOT inherit trust's physical override, got %v", ov.SystemServices)
	}
	if ov := m["reth0.10"]; ov == nil || !eqStr(ov.SystemServices, []string{"ping"}) {
		t.Errorf("reth0.10 (owned by trust) effective = %v, want [ping]", ov)
	}
}
