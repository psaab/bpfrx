package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildZoneIDsMatchesStableSSOT pins the HA invariant (#3075): the daemon's
// buildZoneIDs (used to translate HA session deltas to local zone ids) MUST
// produce byte-identical ids to config.StableZoneID — the same SSOT the
// dataplane compiler (pkg/dataplane.assignZoneIDs) uses to install the live
// zone table. If the two ever diverge, a synced session delta resolves to a
// different local zone than the one the compiler installed, which is exactly
// the mis-map #3075 fixes. Because both nodes compute the id purely from the
// zone NAME, node0 and node1 agree by construction (no per-node id state).
//
// Reverting buildZoneIDs to the sorted 1..N positional loop makes this RED.
func TestBuildZoneIDsMatchesStableSSOT(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {},
		"untrust": {},
		"dmz":     {},
		"wan":     {},
		"lan":     {},
		"mgmt":    {},
	}
	ids := buildZoneIDs(cfg)
	if len(ids) != len(cfg.Security.Zones) {
		t.Fatalf("buildZoneIDs returned %d ids, want %d", len(ids), len(cfg.Security.Zones))
	}
	for name := range cfg.Security.Zones {
		want := config.StableZoneID(name)
		if ids[name] != want {
			t.Fatalf("buildZoneIDs[%q] = %d, want config.StableZoneID = %d (HA-symmetry / sorted-positional revert?)", name, ids[name], want)
		}
		if ids[name] == 0 {
			t.Fatalf("buildZoneIDs[%q] = 0", name)
		}
	}
}

// TestBuildZoneIDsStableAcrossEarlierZoneAdd mirrors the dataplane-side
// fail-on-revert at the HA translation boundary: adding an earlier-sorting zone
// must not renumber a surviving zone (it would under the old sorted scheme).
func TestBuildZoneIDsStableAcrossEarlierZoneAdd(t *testing.T) {
	before := buildZoneIDs(&config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{"trust": {}, "untrust": {}},
	}})
	after := buildZoneIDs(&config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{"alpha": {}, "trust": {}, "untrust": {}},
	}})
	if before["untrust"] != after["untrust"] {
		t.Fatalf("untrust id moved across earlier-zone add: %d -> %d", before["untrust"], after["untrust"])
	}
}
