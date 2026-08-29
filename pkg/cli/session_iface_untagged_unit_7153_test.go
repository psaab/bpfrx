package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7153: an UNTAGGED unit N > 0 never resolved. The map keyed it under its unit
// NUMBER while every session row for it carries wire VID 0, so
// sessionFilter.resolveIngressIfaces missed and fell back to every interface
// bound to the ifindex — silently widening a filter the operator wrote to be
// exact.
//
// The table is the four config shapes from the issue, and the third row is the
// defect. The first two are the controls that stop the fix being "return 0
// always": an explicit vlan-id must still key on it, which is what the real
// cluster config (docs/ha-cluster-userspace.conf) uses.
func TestUntaggedUnitResolvesOnWireVID_7153(t *testing.T) {
	for _, tc := range []struct {
		name    string
		unit    *config.InterfaceUnit
		wantVID uint16
	}{
		{"explicit vlan-id keys on it", &config.InterfaceUnit{Number: 50, VlanID: 50}, 50},
		{"vlan-id differs from number", &config.InterfaceUnit{Number: 80, VlanID: 50}, 50},
		{"UNTAGGED unit N>0 keys on 0", &config.InterfaceUnit{Number: 3}, 0},
		{"unit 0", &config.InterfaceUnit{Number: 0}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionDisplayVLANID(tc.unit); got != tc.wantVID {
				t.Errorf("sessionDisplayVLANID(%+v) = %d, want %d", tc.unit, got, tc.wantVID)
			}
		})
	}
}

// End to end through the map builder, which is where the miss actually bit.
func TestUntaggedUnitIsReachableInTheEgressMap_7153(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
					3: {Number: 3}, // no vlan-id -> untagged
				}},
			},
		},
	}
	m := buildSessionEgressIfacesWithLookup(cfg, func(name string) (int, error) {
		if name == "ge-0-0-0" {
			return 42, nil
		}
		t.Fatalf("unexpected lookup %q", name)
		return 0, nil
	})

	// The key a session row for this unit actually carries.
	if got, ok := m[sessionIfaceKey{ifindex: 42, vlanID: 0}]; !ok || got != "ge-0/0/0.3" {
		t.Errorf("the WIRE key {42,0} does not resolve (got %q, ok=%v). Session rows for an "+
			"untagged unit carry VID 0, so this is the only key that can match one; before "+
			"#7153 the unit was filed under {42,3} and resolveIngressIfaces fell back to "+
			"every interface on the ifindex", got, ok)
	}
	// And the old key must be gone, or the map merely gained an entry and the
	// stale one still shadows a real unit 3 elsewhere.
	if got, ok := m[sessionIfaceKey{ifindex: 42, vlanID: 3}]; ok {
		t.Errorf("the unit is STILL filed under its number as {42,3} -> %q; the number is not "+
			"a wire VID and nothing keys there", got)
	}
}

// Two units with no vlan-id on one interface collide on {ifindex, 0} — correct,
// since only one can own the untagged traffic. First-write-wins over RangeUnits'
// ordering must resolve it deterministically to the lowest unit rather than
// whichever map iteration happened to land last.
func TestUntaggedCollisionResolvesToLowestUnit_7153(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0},
					3: {Number: 3},
				}},
			},
		},
	}
	for i := 0; i < 8; i++ {
		m := buildSessionEgressIfacesWithLookup(cfg, func(string) (int, error) { return 42, nil })
		got := m[sessionIfaceKey{ifindex: 42, vlanID: 0}]
		if got != "ge-0/0/0" {
			t.Fatalf("iteration %d: {42,0} = %q, want \"ge-0/0/0\" — two untagged units "+
				"collide on VID 0 and the resolution must be deterministic, not "+
				"map-iteration order", i, got)
		}
	}
}
