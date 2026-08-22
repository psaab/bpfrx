package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6311 — the chassis-cluster node id must reach the helper on the snapshot so
// the Rust session-id allocator can fold it into the id namespace.
//
// Without it, both HA nodes namespace session ids by worker index alone, and
// since both run the SAME worker set (queue indices 0..N) with per-worker
// counters that both start at 1, a peer id the standby adopts verbatim (#5212)
// collides with the importing node's own id for that worker.

func nodeIDSnapshotConfig(nodeID int, clustered bool) *config.Config {
	cfg := &config.Config{}
	if clustered {
		cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1, NodeID: nodeID}
	}
	return cfg
}

// TestSnapshotCarriesClusterNodeID_6311 is the WIRING guard: the production
// snapshot builder must stamp the node id, not merely have a helper capable of
// computing it.
//
// RED on revert: drop `NodeID: clusterNodeID(cfg)` from the ConfigSnapshot
// literal in builder.go and the node-1 assertion fires.
func TestSnapshotCarriesClusterNodeID_6311(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want uint8
	}{
		{"node 0", nodeIDSnapshotConfig(0, true), 0},
		{"node 1", nodeIDSnapshotConfig(1, true), 1},
		{"standalone (no cluster stanza)", nodeIDSnapshotConfig(0, false), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap, err := buildSnapshot(tc.cfg, config.UserspaceConfig{}, 1, 0)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			if snap.NodeID != tc.want {
				t.Fatalf("snapshot NodeID = %d, want %d — the helper cannot namespace "+
					"session ids by node without it (#6311)", snap.NodeID, tc.want)
			}
		})
	}
}

// TestSnapshotNodeIDWireKeyAndOmission_6311 pins the wire contract the Rust
// `#[serde(rename = "node_id", default)]` field reads. A renamed key or a
// non-omitempty zero would each be a silent one-way break: the helper would
// deserialize its default (0) and node 1 would keep minting ids in node 0's
// namespace, with nothing failing.
func TestSnapshotNodeIDWireKeyAndOmission_6311(t *testing.T) {
	snap, err := buildSnapshot(nodeIDSnapshotConfig(1, true), config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, ok := wire["node_id"]
	if !ok {
		t.Fatal("#6311: the snapshot wire carries no `node_id` key — the helper's " +
			"serde(default) would silently leave node 1 in node 0's id namespace")
	}
	if string(got) != "1" {
		t.Fatalf("wire node_id = %s, want 1", got)
	}

	// Node 0 is the default on both sides, so omitempty must drop it — that is
	// what keeps the field additive for an older helper.
	snap0, err := buildSnapshot(nodeIDSnapshotConfig(0, true), config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot(node 0): %v", err)
	}
	raw0, err := json.Marshal(snap0)
	if err != nil {
		t.Fatalf("marshal(node 0): %v", err)
	}
	var wire0 map[string]json.RawMessage
	if err := json.Unmarshal(raw0, &wire0); err != nil {
		t.Fatalf("unmarshal(node 0): %v", err)
	}
	if _, present := wire0["node_id"]; present {
		t.Fatal("node 0 must omit `node_id` — the field is additive and 0 is the " +
			"default on both sides")
	}
}

// TestClusterNodeIDNarrowsToOneBit_6311 pins the narrowing. The helper uses the
// value as a single discriminator BIT, so anything outside 0..1 has to fold
// deterministically here rather than reaching the wire and being folded (or
// asserted on) inside the dataplane. 0..1 is already guaranteed upstream —
// parseNodeIDFileContent rejects anything else, and IsSupportedClusterNodeID
// pins the two-node topology — so this is defence in depth for the wire field.
func TestClusterNodeIDNarrowsToOneBit_6311(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want uint8
	}{
		{0, 0},
		{1, 1},
		{-1, 0}, // unset/sentinel
		{2, 1},  // impossible topology: never silently aliases node 0
	} {
		if got := clusterNodeID(nodeIDSnapshotConfig(tc.in, true)); got != tc.want {
			t.Fatalf("clusterNodeID(node %d) = %d, want %d", tc.in, got, tc.want)
		}
	}
	if got := clusterNodeID(nil); got != 0 {
		t.Fatalf("clusterNodeID(nil) = %d, want 0", got)
	}
}
