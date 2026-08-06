package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// stableIDNodeConfig builds one cluster node's view of the shared topology,
// mirroring docs/ha-cluster-userspace.conf: the reth MEMBER name carries the
// node's FPC (ge-0/0/x on node 0, ge-7/0/x on node 1) while the reth and its
// units are spelled identically in both nodes' configs.
func stableIDNodeConfig(fpc string) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-" + fpc + "/0/2": {
					Name:            "ge-" + fpc + "/0/2",
					RedundantParent: "reth0",
				},
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						50: {Number: 50, VlanID: 50},
						80: {Number: 80, VlanID: 80},
					},
				},
			},
		},
	}
}

// TestInterfaceSnapshotCarriesClusterStableID4983 binds the POPULATION, not
// just the field: buildInterfaceSnapshots must stamp each row's cluster-stable
// id, and the id a row carries must be the same on both cluster nodes for the
// interface that means the same thing on both.
//
// Reverting the StableID assignments in buildInterfaceSnapshots reds this on
// an assertion — every row would carry 0 and the dataplane would have nothing
// to stamp on a session.
func TestInterfaceSnapshotCarriesClusterStableID4983(t *testing.T) {
	node0 := buildInterfaceSnapshots(stableIDNodeConfig("0"))
	node1 := buildInterfaceSnapshots(stableIDNodeConfig("7"))

	byName := func(rows []InterfaceSnapshot) map[string]InterfaceSnapshot {
		m := make(map[string]InterfaceSnapshot, len(rows))
		for _, r := range rows {
			m[r.Name] = r
		}
		return m
	}
	n0, n1 := byName(node0), byName(node1)

	t.Run("the reth unit rows carry a nonzero id", func(t *testing.T) {
		for _, name := range []string{"reth0.50", "reth0.80"} {
			row, ok := n0[name]
			if !ok {
				t.Fatalf("no snapshot row for %s", name)
			}
			if row.StableID == 0 {
				t.Errorf("%s carries StableID 0; 0 is the reserved "+
					"no-identity-carried sentinel, so the dataplane would have "+
					"nothing to stamp on a session ingressing there (#4983)", name)
			}
		}
	})

	t.Run("the two units of one trunk NIC carry DIFFERENT ids", func(t *testing.T) {
		if n0["reth0.50"].StableID == n0["reth0.80"].StableID {
			t.Error("reth0.50 and reth0.80 share a physical NIC and, in this " +
				"topology, a zone — collapsing them onto one id reintroduces " +
				"exactly the cross-interface match #4983 removes")
		}
	})

	t.Run("the member row resolves onto its reth, identically on both nodes", func(t *testing.T) {
		got0 := n0["ge-0/0/2"].StableID
		got1 := n1["ge-7/0/2"].StableID
		if got0 == 0 || got1 == 0 {
			t.Fatalf("member rows carry StableID 0 (node0=%d node1=%d)", got0, got1)
		}
		if got0 != got1 {
			t.Errorf("node0 ge-0/0/2 -> %d but node1 ge-7/0/2 -> %d: the same reth0 "+
				"member slot must carry ONE id, or a session synced across the "+
				"cluster names a different interface on the peer (#4983)", got0, got1)
		}
		if want := config.StableInterfaceID("reth0"); got0 != want {
			t.Errorf("member StableID = %d, want reth0's id %d", got0, want)
		}
	})

	t.Run("reth0.50 is identical across nodes", func(t *testing.T) {
		if n0["reth0.50"].StableID != n1["reth0.50"].StableID {
			t.Error("reth0.50 is spelled identically in both nodes' configs and must " +
				"carry an identical id")
		}
	})
}

// TestInterfaceSnapshotStableIDWireTag4983 pins the JSON key against the Rust
// `#[serde(rename = "stable_id", default)]` declaration on the other side of
// this wire. A field added on one side only is a no-transit hazard (#1961), so
// the tag is asserted literally rather than assumed.
func TestInterfaceSnapshotStableIDWireTag4983(t *testing.T) {
	blob, err := json.Marshal(InterfaceSnapshot{Name: "reth0.50", StableID: 3735928559})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(blob, &generic); err != nil {
		t.Fatalf("unmarshal to generic: %v", err)
	}
	raw, ok := generic["stable_id"]
	if !ok {
		t.Fatalf("marshalled InterfaceSnapshot has no \"stable_id\" key (got keys %v); "+
			"the Rust side reads exactly that name", stableIDKeys(generic))
	}
	if got, want := raw.(float64), float64(3735928559); got != want {
		t.Errorf("stable_id encoded as %v, want %v", got, want)
	}

	t.Run("an absent key decodes to the 0 sentinel", func(t *testing.T) {
		// The rolling-upgrade case in the other direction: a snapshot from a
		// pre-#4983 Go binary carries no stable_id at all. It must decode to 0
		// — "no identity carried" — not to a garbage id that would name some
		// unrelated interface.
		var round InterfaceSnapshot
		if err := json.Unmarshal([]byte(`{"name":"reth0.50"}`), &round); err != nil {
			t.Fatalf("unmarshal legacy payload: %v", err)
		}
		if round.StableID != 0 {
			t.Errorf("absent stable_id decoded to %d, want 0", round.StableID)
		}
	})
}

func stableIDKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
