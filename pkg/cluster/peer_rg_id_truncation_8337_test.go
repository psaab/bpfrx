package cluster

import (
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// lenientClusterConfig8337 compiles a chassis-cluster config carrying `rgID`
// through the LENIENT compiler.
//
// #8337: going through `CompileConfigLenient` rather than hand-building a
// `config.ClusterConfig` is load-bearing, not ceremony. The strict compiler
// REFUSES an id above `MaxRedundancyGroups`, so a strict fixture cannot
// construct the state at all and a test built on one would pass against the
// broken code by never entering it. The lenient compiler is what
// `Store.Load` and `Store.SyncApply` use — persisted-config boot and HA peer
// sync — so this fixture is the reachable path, not a synthetic one.
func lenientClusterConfig8337(t *testing.T, rgID int) *config.ClusterConfig {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		fmt.Sprintf("set chassis cluster redundancy-group %d node 0 priority 200", rgID),
		fmt.Sprintf("set chassis cluster redundancy-group %d node 1 priority 100", rgID),
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatalf("lenient compile produced no cluster config for rg %d", rgID)
	}
	cc := cfg.Chassis.Cluster
	var found bool
	for _, rg := range cc.RedundancyGroups {
		if rg.ID == rgID {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient compile dropped redundancy-group %d — the fixture must "+
			"actually carry the id under test, or the assertions below are vacuous", rgID)
	}
	return cc
}

// #8337: a peer's redundancy group must be found under the id the local config
// uses, including when that id does not survive the single-byte wire field.
//
// THE DEFECT. `buildHeartbeat` narrowed the id with a bare `uint8(...)` — beside
// a `clampWireWeight` that saturates, so the hazard was known — and
// `handlePeerHeartbeat` keyed `peerGroups` by whatever byte arrived, while every
// reader (election.go, status.go, failover.go, upgrade_drain.go, group_state.go)
// indexes that map by the RAW config id. For any id whose low byte differs the
// two keys never meet, and `election.go` turns the miss into
// `peerAlive && peerGroup == nil -> electLocalPrimary, "Peer has no RG info"`.
// A node receiving and parsing its peer's heartbeats concludes the peer has no
// RG info and elects itself primary — on a cluster where the peer has done the
// same, a SECOND PRIMARY.
//
// THE PACKET IS BUILT BY THE PEER, not hand-written. Writing `GroupID: 255` here
// would encode the fix's own output as the fixture and pass even if the SENDER
// were wrong; what must hold is that the two sides AGREE, so the peer's real
// `buildHeartbeat` produces the packet the local node consumes.
//
// Both cases run: a normal in-range id is the over-correction control — getting
// that wrong breaks every working cluster, and it would not show in the 300 case.
func TestPeerRedundancyGroupIsKeyedByLocalConfigID8337(t *testing.T) {
	for _, tc := range []struct {
		name string
		rgID int
	}{
		{"in-range control (low byte == id)", 1},
		{"truncating id (low byte != id)", 300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc := lenientClusterConfig8337(t, tc.rgID)

			peer := NewManager(1, 1)
			peer.UpdateConfig(cc)
			drainEvents(peer, 8)
			pkt := peer.buildHeartbeat()
			if len(pkt.Groups) == 0 {
				t.Fatalf("peer advertised no groups for rg %d — the fixture never "+
					"reaches the wire path under test", tc.rgID)
			}

			local := NewManager(0, 1)
			local.UpdateConfig(cc)
			drainEvents(local, 8)
			local.handlePeerHeartbeat(pkt)

			states := local.PeerGroupStates()
			if _, ok := states[tc.rgID]; !ok {
				t.Fatalf("peer redundancy group %d is absent from peerGroups (keys: %v). "+
					"Every reader of that map indexes it by the raw config id, so a miss "+
					"here is `peerAlive && peerGroup == nil` in election.go — the node "+
					"elects itself primary while its peer is alive and advertising the "+
					"group (#8337)", tc.rgID, keysOf8337(states))
			}
			if got := states[tc.rgID].GroupID; got != tc.rgID {
				t.Fatalf("peerGroups[%d].GroupID = %d, want %d — the stored state must "+
					"carry the local config id, not the wire byte (#8337)",
					tc.rgID, got, tc.rgID)
			}
		})
	}
}

func keysOf8337(m map[int]PeerGroupState) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
