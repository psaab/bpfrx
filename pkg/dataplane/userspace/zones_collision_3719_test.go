// #3719: on the lenient / HA-sync / pre-#3075-persisted path two security zone
// names can fold to the same StableZoneID. Before this fix buildZoneSnapshots
// published BOTH with the same numeric id, and the Rust id-keyed maps merged the
// two zones (one zone's reverse name / host-inbound set / tcp-rst bit / counters
// stood in for the other) — a zone-isolation failure the lenient warning falsely
// claimed was quarantined. quarantineCollidingZones now DROPS the later-sorting
// colliding zone from the wire (and unzones its interfaces / drops its policies
// so no dangling reference bricks the helper preflight), matching the warning.
//
// These tests go RED if the quarantine pass is removed from buildSnapshot (both
// colliding zones publish with the same id) — the H02/M08 regression they guard.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestQuarantineCollidingZonesDropsAndScrubs exercises the pass directly on a
// hand-built snapshot carrying the verified colliding pair z174/z214 plus a
// distinct zone. It must drop the later-sorting zone (z214), keep the survivor
// (z174) and the distinct zone, unzone z214's interface, drop z214's policy, and
// report the collision — leaving no two zones sharing an id.
func TestQuarantineCollidingZonesDropsAndScrubs(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatalf("test premise broken: z174/z214 no longer collide under the frozen fold")
	}
	collideID := config.StableZoneID("z174")
	snap := &ConfigSnapshot{
		Zones: []ZoneSnapshot{
			{Name: "trust", ID: config.StableZoneID("trust")},
			{Name: "z174", ID: config.StableZoneID("z174")},
			{Name: "z214", ID: config.StableZoneID("z214")},
		},
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0-0-0.0", Zone: "z174"},
			{Name: "ge-0-0-1.0", Zone: "z214"},
			{Name: "ge-0-0-2.0", Zone: "trust"},
		},
		Policies: []PolicyRuleSnapshot{
			{Name: "p-survivor", FromZone: "z174", ToZone: "trust"},
			{Name: "p-quarantined-from", FromZone: "z214", ToZone: "trust"},
			{Name: "p-quarantined-to", FromZone: "trust", ToZone: "z214"},
			{Name: "p-global", FromZone: "junos-global", ToZone: "junos-global"},
		},
	}

	collisions := quarantineCollidingZones(snap)

	// The colliding zone is dropped; the survivor + distinct zone remain.
	names := map[string]uint16{}
	for _, z := range snap.Zones {
		if prev, dup := names[z.Name]; dup {
			t.Fatalf("zone %q appears twice (%d, %d)", z.Name, prev, z.ID)
		}
		names[z.Name] = z.ID
	}
	if _, ok := names["z214"]; ok {
		t.Fatalf("quarantined zone z214 still published: %v", names)
	}
	if _, ok := names["z174"]; !ok {
		t.Fatalf("survivor zone z174 was dropped: %v", names)
	}
	if _, ok := names["trust"]; !ok {
		t.Fatalf("distinct zone trust was dropped: %v", names)
	}
	// The core invariant: no two published zones share a numeric id.
	seen := map[uint16]string{}
	for n, id := range names {
		if prev, dup := seen[id]; dup {
			t.Fatalf("two zones share id %d after quarantine: %q and %q", id, prev, n)
		}
		seen[id] = n
	}

	// z214's interface is unzoned (fail closed); the others keep their zone.
	byIface := map[string]string{}
	for _, i := range snap.Interfaces {
		byIface[i.Name] = i.Zone
	}
	if z := byIface["ge-0-0-1.0"]; z != "" {
		t.Fatalf("interface in quarantined zone still bound to %q, want unzoned", z)
	}
	if z := byIface["ge-0-0-0.0"]; z != "z174" {
		t.Fatalf("survivor-zone interface lost its binding: %q", z)
	}
	if z := byIface["ge-0-0-2.0"]; z != "trust" {
		t.Fatalf("distinct-zone interface lost its binding: %q", z)
	}

	// Policies referencing z214 (from OR to) are dropped; survivor + global kept.
	polNames := map[string]bool{}
	for _, p := range snap.Policies {
		polNames[p.Name] = true
	}
	if polNames["p-quarantined-from"] || polNames["p-quarantined-to"] {
		t.Fatalf("policy referencing quarantined zone z214 survived: %v", polNames)
	}
	if !polNames["p-survivor"] || !polNames["p-global"] {
		t.Fatalf("non-colliding policy was wrongly dropped: %v", polNames)
	}

	// The collision is reported with the survivor + quarantined names and id.
	if len(collisions) != 1 {
		t.Fatalf("got %d collisions, want 1: %v", len(collisions), collisions)
	}
	c := collisions[0]
	if c.ID != collideID || c.Survivor != "z174" || c.Quarantined != "z214" {
		t.Fatalf("collision record = %+v, want {ID:%d Survivor:z174 Quarantined:z214}", c, collideID)
	}
}

// TestBuildSnapshotQuarantinesCollidingZone drives the REAL publish path
// (buildSnapshot): a config with the colliding pair must yield a snapshot that
// publishes neither zone twice under one id, drops the later-sorting zone, and
// records the collision on the (unexported) diagnostic the manager reads. On a
// revert (buildZoneSnapshots emits both) this fails: two ZoneSnapshots carry id
// 53547.
func TestBuildSnapshotQuarantinesCollidingZone(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust"},
		"z174":  {Name: "z174"},
		"z214":  {Name: "z214"},
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	seen := map[uint16]string{}
	var haveZ214 bool
	for _, z := range snap.Zones {
		if z.Name == "z214" {
			haveZ214 = true
		}
		if prev, dup := seen[z.ID]; dup {
			t.Fatalf("two published zones share id %d: %q and %q (#3719 quarantine reverted?)", z.ID, prev, z.Name)
		}
		seen[z.ID] = z.Name
	}
	if haveZ214 {
		t.Fatalf("later-sorting colliding zone z214 was published, want quarantined")
	}
	if len(snap.zoneIDCollisions) != 1 {
		t.Fatalf("snap.zoneIDCollisions = %v, want exactly one collision", snap.zoneIDCollisions)
	}
	c := snap.zoneIDCollisions[0]
	if c.Survivor != "z174" || c.Quarantined != "z214" {
		t.Fatalf("collision = %+v, want survivor z174 / quarantined z214", c)
	}
}

// TestBuildSnapshotNoCollisionPublishesAll: the common case is untouched — an
// ordinary distinct-folding zone set publishes every zone and records no
// collision (no false positive).
func TestBuildSnapshotNoCollisionPublishesAll(t *testing.T) {
	cfg := threeZoneCfg()
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if len(snap.Zones) != len(cfg.Security.Zones) {
		t.Fatalf("published %d zones, want %d (quarantine false positive?)", len(snap.Zones), len(cfg.Security.Zones))
	}
	if len(snap.zoneIDCollisions) != 0 {
		t.Fatalf("recorded a collision on a distinct-folding set: %v", snap.zoneIDCollisions)
	}
}
