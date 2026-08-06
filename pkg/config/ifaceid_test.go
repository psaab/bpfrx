package config

import (
	"strconv"
	"testing"
)

// nodeConfig builds one chassis-cluster node's view of the SAME logical
// topology. The member names differ by node exactly as they do in
// docs/ha-cluster-userspace.conf — node 0 uses FPC 0 (ge-0/0/1, ge-0/0/2),
// node 1 uses FPC 7 (ge-7/0/1, ge-7/0/2) — while the redundant-parent names
// and the reth units they carry are byte-identical on both.
func nodeConfig(nodeID, fpc int) *Config {
	member := func(port int) string {
		return "ge-" + strconv.Itoa(fpc) + "/0/" + strconv.Itoa(port)
	}
	return &Config{
		Chassis: ChassisConfig{Cluster: &ClusterConfig{NodeID: nodeID}},
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				member(1): {Name: member(1), RedundantParent: "reth1"},
				member(2): {Name: member(2), RedundantParent: "reth0"},
				"reth0": {
					Name: "reth0",
					Units: map[int]*InterfaceUnit{
						50: {Number: 50, VlanID: 50},
						80: {Number: 80, VlanID: 80},
					},
				},
				"reth1": {
					Name:  "reth1",
					Units: map[int]*InterfaceUnit{0: {Number: 0}},
				},
				"fxp0": {
					Name:  "fxp0",
					Units: map[int]*InterfaceUnit{0: {Number: 0}},
				},
			},
		},
	}
}

// TestClusterStableInterfaceIDAgreesAcrossNodes4983 is the load-bearing proof
// for #4983's cross-node story: the ingress-interface identity a session
// records on node 0 must mean the SAME interface when the session is read on
// node 1 after a failover.
//
// A raw ifindex cannot do this — node 0's ge-0/0/1 and node 1's ge-7/0/1 are
// different numbers (and different NAMES) for the same member slot of the same
// reth — which is why the identity is a fold of the RETH-RELATIVE name.
// Reverting ClusterStableInterfaceName to the identity function (dropping the
// explicit redundant-parent resolution) reds this on an assertion.
func TestClusterStableInterfaceIDAgreesAcrossNodes4983(t *testing.T) {
	node0 := nodeConfig(0, 0)
	node1 := nodeConfig(1, 7)

	t.Run("the same member slot folds to one id on both nodes", func(t *testing.T) {
		got0 := InterfaceStableID(node0, "ge-0/0/1")
		got1 := InterfaceStableID(node1, "ge-7/0/1")
		if got0 != got1 {
			t.Fatalf("node0 ge-0/0/1 -> %d, node1 ge-7/0/1 -> %d: the same reth1 member "+
				"slot must fold to ONE id, or a session synced across the cluster names a "+
				"different interface on the peer than it did on the node that opened it (#4983)",
				got0, got1)
		}
		if want := StableInterfaceID("reth1"); got0 != want {
			t.Fatalf("member id = %d, want the reth-relative id %d: the identity must be the "+
				"redundant PARENT's, since that is the name both nodes' configs share and the "+
				"name the zone is bound to", got0, want)
		}
	})

	t.Run("the WAN member slot likewise", func(t *testing.T) {
		if InterfaceStableID(node0, "ge-0/0/2") != InterfaceStableID(node1, "ge-7/0/2") {
			t.Error("node0 ge-0/0/2 and node1 ge-7/0/2 are the same reth0 member slot and " +
				"must fold to one id (#4983)")
		}
	})

	t.Run("a unit suffix rides the resolution", func(t *testing.T) {
		got0 := InterfaceStableID(node0, "ge-0/0/2.50")
		got1 := InterfaceStableID(node1, "ge-7/0/2.50")
		if got0 != got1 {
			t.Errorf("member unit .50 must fold identically across nodes: %d vs %d", got0, got1)
		}
		if want := StableInterfaceID("reth0.50"); got0 != want {
			t.Errorf("member unit id = %d, want reth0.50's id %d — the unit suffix must be "+
				"carried onto the redundant parent, not dropped", got0, want)
		}
	})

	// Over-reach guards. These pin the behaviour #4983 does NOT change, and
	// stay green if the reth resolution is reverted.
	t.Run("different reths keep different ids", func(t *testing.T) {
		if InterfaceStableID(node0, "ge-0/0/1") == InterfaceStableID(node0, "ge-0/0/2") {
			t.Error("members of DIFFERENT reths must not collapse onto one id — that would " +
				"reintroduce the cross-interface match #4983 removes")
		}
		if StableInterfaceID("reth0") == StableInterfaceID("reth1") {
			t.Error("reth0 and reth1 must not fold together")
		}
	})

	t.Run("distinct units of one reth keep distinct ids", func(t *testing.T) {
		if StableInterfaceID("reth0.50") == StableInterfaceID("reth0.80") {
			t.Error("reth0.50 and reth0.80 are different interfaces in the same zone on the " +
				"same trunk NIC — the exact pair #4983 must separate")
		}
	})

	t.Run("a non-member interface is already node-independent", func(t *testing.T) {
		if got := ClusterStableInterfaceName(node0, "fxp0"); got != "fxp0" {
			t.Errorf("ClusterStableInterfaceName(fxp0) = %q, want fxp0 unchanged", got)
		}
		if InterfaceStableID(node0, "fxp0") != InterfaceStableID(node1, "fxp0") {
			t.Error("fxp0 is spelled identically on both nodes and must fold identically")
		}
	})

	t.Run("id is never zero", func(t *testing.T) {
		for _, n := range []string{"", "reth0", "ge-0/0/1", "fxp0", "reth0.50"} {
			if StableInterfaceID(n) == 0 {
				t.Errorf("StableInterfaceID(%q) = 0, but 0 is the reserved "+
					"no-identity-carried sentinel", n)
			}
		}
	})
}

// TestBuildStableInterfaceIDsResolvesMembersToTheReth4983 pins the map the CLI
// resolves a session's recorded id through: a member and its reth must both
// report the RETH-relative display name, since that is what the operator
// configured the zone with and what means the same thing on either node.
func TestBuildStableInterfaceIDsResolvesMembersToTheReth4983(t *testing.T) {
	ids := BuildStableInterfaceIDs(nodeConfig(0, 0))

	if got := ids[StableInterfaceID("reth1")]; got != "reth1" {
		t.Errorf("id for reth1 resolves to %q, want \"reth1\" — a member and its reth share "+
			"an id and the reth-relative name is the one to report", got)
	}
	if got := ids[StableInterfaceID("reth0.50")]; got != "reth0.50" {
		t.Errorf("id for reth0.50 resolves to %q, want \"reth0.50\"", got)
	}
	if got := ids[StableInterfaceID("reth0.80")]; got != "reth0.80" {
		t.Errorf("id for reth0.80 resolves to %q, want \"reth0.80\"", got)
	}
	if got := ids[StableInterfaceID("fxp0")]; got != "fxp0" {
		t.Errorf("id for fxp0 resolves to %q, want \"fxp0\"", got)
	}
}

// TestBuildStableInterfaceIDsDropsCollidingID4983 exercises the collision
// branch with a REAL collision, not a mocked one.
//
// `ge-37/3/100` and `ge-37/6/106` are both legal Junos interface names and
// both fold to 914579331 under StableInterfaceID (found by exhaustive search
// over the ge/xe/et name space; the fold is 32-bit, so collisions exist and
// are simply rare). Two genuinely different interfaces on one id must be
// DROPPED from the map rather than resolved to whichever name was inserted
// last: reporting one of them would be exactly the cross-interface match
// #4983 exists to remove, whereas dropping it costs only precision — the
// caller falls back to the zone approximation.
func TestBuildStableInterfaceIDsDropsCollidingID4983(t *testing.T) {
	const (
		nameA      = "ge-37/3/100"
		nameB      = "ge-37/6/106"
		collidedID = uint32(914579331)
	)
	// Guard the fixture itself: if the fold ever changes, these stop colliding
	// and the test would silently stop covering the branch.
	if StableInterfaceID(nameA) != collidedID || StableInterfaceID(nameB) != collidedID {
		t.Fatalf("fixture stale: %s -> %d, %s -> %d, expected both %d. The collision pair "+
			"must actually collide or this test proves nothing",
			nameA, StableInterfaceID(nameA), nameB, StableInterfaceID(nameB), collidedID)
	}

	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				nameA:      {Name: nameA},
				nameB:      {Name: nameB},
				"ge-0/0/0": {Name: "ge-0/0/0"},
			},
		},
	}
	ids := BuildStableInterfaceIDs(cfg)

	if got, ok := ids[collidedID]; ok {
		t.Errorf("colliding id %d resolved to %q; it must be dropped so the caller falls "+
			"back to the zone approximation instead of naming one of two different "+
			"interfaces (#4983)", collidedID, got)
	}
	// The collision must be scoped to the colliding id — an unrelated
	// interface keeps resolving.
	if got := ids[StableInterfaceID("ge-0/0/0")]; got != "ge-0/0/0" {
		t.Errorf("an unrelated interface resolved to %q, want ge-0/0/0: one collision must "+
			"not poison the whole map", got)
	}
}
