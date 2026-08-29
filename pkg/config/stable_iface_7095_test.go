package config

import "testing"

// stable_iface_7095_test.go — #7095.
//
// The whole premise of putting an ingress identity on the HA wire is that BOTH
// NODES AGREE on it. So the cells assert the agreement between two configs that
// differ exactly as the two chassis do — node id and member slot — rather than
// pinning either side to a literal. A literal would encode which node I trusted,
// and the failure this design exists to prevent is precisely one node naming a
// device the other does not have.

// clusterCfg7095 builds one node's view: the same reth topology, with the member
// slot and node id that node actually has.
func clusterCfg7095(nodeID, slot int) *Config {
	c := &Config{}
	c.Chassis.Cluster = &ClusterConfig{NodeID: nodeID}
	c.Interfaces.Interfaces = map[string]*InterfaceConfig{}
	member := func(name, reth string) {
		c.Interfaces.Interfaces[name] = &InterfaceConfig{
			Name:            name,
			RedundantParent: reth,
		}
	}
	// node 0 uses FPC 0, node 1 uses FPC 7 — the loss-cluster shape.
	// Config carries the JUNOS spelling; the lookups below use the LINUX one,
	// which is what an ifindex resolves to. If the two are not normalised the
	// members never match a reth and both nodes fold their own local name —
	// silently, since an unmatched name is still a name.
	wan := "ge-" + itoa7095(slot) + "/0/2"
	lan := "ge-" + itoa7095(slot) + "/0/1"
	member(wan, "reth0")
	member(lan, "reth1")
	c.Interfaces.Interfaces["reth0"] = &InterfaceConfig{
		Name:  "reth0",
		Units: map[int]*InterfaceUnit{50: {Number: 50, VlanID: 50}, 80: {Number: 80, VlanID: 80}},
	}
	c.Interfaces.Interfaces["reth1"] = &InterfaceConfig{
		Name:  "reth1",
		Units: map[int]*InterfaceUnit{0: {Number: 0}},
	}
	return c
}

func itoa7095(i int) string { return string(rune('0' + i)) }

// TestStableIfaceNameAgreesAcrossNodes_7095 is the property the wire field
// depends on: the same logical interface folds to the same id on both chassis,
// while each node resolves that id to its OWN device.
func TestStableIfaceNameAgreesAcrossNodes_7095(t *testing.T) {
	n0 := clusterCfg7095(0, 0)
	n1 := clusterCfg7095(1, 7)

	for _, tc := range []struct {
		name       string
		localOn0   string
		vlan       uint16
		wantLocal1 string
	}{
		{"reth0_vlan50", "ge-0-0-2", 50, "ge-7/0/2.50"},
		{"reth0_vlan80", "ge-0-0-2", 80, "ge-7/0/2.80"},
		{"reth1_untagged", "ge-0-0-1", 0, "ge-7/0/1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stable0 := n0.ClusterStableIfaceName(tc.localOn0, tc.vlan)
			if stable0 == "" {
				t.Fatal("node 0 produced no cluster-stable name for its own member")
			}
			// The same logical interface, named locally on node 1.
			local1 := "ge-7" + tc.localOn0[len("ge-0"):]
			stable1 := n1.ClusterStableIfaceName(local1, tc.vlan)

			if stable0 != stable1 {
				t.Fatalf("the two nodes disagree on the stable name: node0(%q)=%q, "+
					"node1(%q)=%q. The wire field is only meaningful if this holds — a "+
					"disagreement means the importing node resolves the id to a different "+
					"device, which is the confidently-wrong rendering #6928 refused to ship",
					tc.localOn0, stable0, local1, stable1)
			}
			if StableIfaceID(stable0) != StableIfaceID(stable1) {
				t.Fatalf("names agree (%q) but folds differ: %d vs %d",
					stable0, StableIfaceID(stable0), StableIfaceID(stable1))
			}

			// And each node resolves the shared id back to its OWN member.
			id := StableIfaceID(stable0)
			got1, ok := n1.LocalIfaceForStableID(id)
			if !ok {
				t.Fatalf("node 1 could not resolve the shared id %d back to a local "+
					"interface; a peer session would fall back to the zone approximation "+
					"even though node 1 has the device", id)
			}
			if got1 != tc.wantLocal1 {
				t.Fatalf("node 1 resolved the shared id to %q, want %q — resolving to the "+
					"PEER's device name is the failure mode this design exists to avoid",
					got1, tc.wantLocal1)
			}
			got0, ok := n0.LocalIfaceForStableID(id)
			if !ok || got0 == got1 {
				t.Fatalf("node 0 resolved the shared id to %q (ok=%v); it must resolve to "+
					"its OWN member, which differs from node 1's %q", got0, ok, got1)
			}
		})
	}
}

// TestStableIfaceZeroIsUnknownAndLegacy_7095 pins the sentinel that carries two
// meanings on purpose: an absent field (legacy peer) and a session with no
// knowable ingress interface (#7096's fabric-redirected case) are the same 0,
// and both resolve to "no name" rather than to a device.
func TestStableIfaceZeroIsUnknownAndLegacy_7095(t *testing.T) {
	n0 := clusterCfg7095(0, 0)
	if got := StableIfaceID(""); got != 0 {
		t.Fatalf("StableIfaceID(\"\") = %d, want 0 — the empty name is how a caller "+
			"says 'no identity', and it must land on the same sentinel a legacy peer's "+
			"absent field does", got)
	}
	if name, ok := n0.LocalIfaceForStableID(0); ok || name != "" {
		t.Fatalf("id 0 resolved to %q (ok=%v); 0 means unknown and must never name a "+
			"device", name, ok)
	}
	// A fold for an interface this node does not have is also "no name", not a
	// wrong one — the peer's config being ahead of ours is not an error.
	if name, ok := n0.LocalIfaceForStableID(StableIfaceID("reth9.4000")); ok {
		t.Fatalf("an unknown-to-this-node interface resolved to %q; it must fall back "+
			"to the zone approximation instead", name)
	}
}

// TestStableIfaceIDNeverReturnsTheSentinel_7095 guards the reservation itself.
func TestStableIfaceIDNeverReturnsTheSentinel_7095(t *testing.T) {
	// A broad sweep of plausible names: if any folded to 0 the sentinel would be
	// ambiguous with a real interface, and that session would silently degrade.
	var checked int
	for _, base := range []string{"reth0", "reth1", "reth2", "ge-0-0-0", "ge-7-0-9",
		"fab0", "fxp0", "em0", "st0", "lo0", "xe-1-2-3"} {
		for vlan := 0; vlan <= 4095; vlan += 7 {
			name := base
			if vlan > 0 {
				name = base + "." + itoaSlow7095(vlan)
			}
			checked++
			if StableIfaceID(name) == 0 {
				t.Fatalf("StableIfaceID(%q) == 0, colliding with the unknown sentinel", name)
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d names checked; the sweep is too small to say much", checked)
	}
}

func itoaSlow7095(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
