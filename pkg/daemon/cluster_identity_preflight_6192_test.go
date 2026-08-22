package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sync/semaphore"
)

// clusterCfgID builds a compiled-shaped clustered config with an explicit
// node-id / cluster-id, matching what CompileCandidateGen produces for the
// commit preflight (Chassis.Cluster populated with the resolved identity).
func clusterCfgID(nodeID, clusterID int) *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: clusterID, NodeID: nodeID}
	return cfg
}

// TestClusterIdentityDay2ChangeRejected is the #6192 fail-on-revert gate.
//
// cluster.NewManager(nodeID, clusterID) is constructed exactly once at boot
// (daemon_run.go:1868); Manager.UpdateConfig reconciles only redundancy groups
// and never re-reads node-id / cluster-id. So a day-2 commit that CHANGES
// `chassis cluster node-id` or `cluster-id` is silently accepted while the
// running manager keeps its OLD identity — a partial no-op that takes effect
// only on restart (the same false-success class #5840 fixed for the topology
// flip). clusterIdentityCommitPreflight rejects it BEFORE store promotion / any
// dataplane mutation, comparing the RUNNING manager identity (d.cluster) to the
// candidate.
//
// Reverting the fix (clusterIdentityCommitPreflight returns nil, or dropping
// either half of the identity comparison) makes the FIRST assertion below RED as
// an assertion — exactly one test binds the production reject line. The
// commitAndApply leg then proves the preflight is wired into the commit path and
// that a rejected identity change promotes NOTHING.
func TestClusterIdentityDay2ChangeRejected(t *testing.T) {
	running := cluster.NewManager(0 /*nodeID*/, 1 /*clusterID*/)

	// --- Direct preflight: the precise binding (running-vs-candidate). ---
	// node-id change (0 -> 1), cluster-id unchanged: the #6192 bug.
	err := clusterIdentityCommitPreflight(running, clusterCfgID(1 /*node*/, 1 /*cluster*/))
	if err == nil {
		t.Fatal("changing chassis cluster node-id on a running clustered node must be " +
			"REJECTED (the boot-constructed HA manager cannot be re-keyed live)")
	}
	if !errors.Is(err, errClusterIdentityRequiresRestart) {
		t.Fatalf("rejection must wrap the identity-restart sentinel; got %v", err)
	}
	if !strings.Contains(err.Error(), "node-id") ||
		!strings.Contains(err.Error(), "cluster-id") ||
		!strings.Contains(err.Error(), "restart") {
		t.Fatalf("rejection must carry an actionable node-id/cluster-id/restart "+
			"diagnostic; got %q", err.Error())
	}

	// cluster-id change (1 -> 2), node-id unchanged: the primary reachable case
	// (cluster-id is read straight from config, never stamped, and no existing
	// compile gate catches it).
	if cerr := clusterIdentityCommitPreflight(running, clusterCfgID(0 /*node*/, 2 /*cluster*/)); cerr == nil ||
		!errors.Is(cerr, errClusterIdentityRequiresRestart) {
		t.Fatalf("changing chassis cluster cluster-id on a running clustered node must be "+
			"REJECTED with the identity-restart sentinel; got %v", cerr)
	}

	// --- Controls: an intra-identity edit (same node-id AND cluster-id) passes. ---
	if aerr := clusterIdentityCommitPreflight(running, clusterCfgID(0, 1)); aerr != nil {
		t.Fatalf("same node-id + cluster-id must be accepted (intra-identity edit); got %v", aerr)
	}

	// --- Scope: cases the topology gate (#5840) owns are no-ops here. ---
	// No running HA manager + clustered candidate: the standalone->cluster /
	// #4179 config-less transition is the topology gate's job, not this one.
	if nerr := clusterIdentityCommitPreflight(nil /*running*/, clusterCfgID(1, 2)); nerr != nil {
		t.Fatalf("nil running manager must be a no-op here (topology gate owns it); got %v", nerr)
	}
	// Running HA manager + standalone candidate: the cluster->standalone teardown
	// is likewise the topology gate's job.
	if serr := clusterIdentityCommitPreflight(running, standaloneCfg()); serr != nil {
		t.Fatalf("standalone candidate must be a no-op here (topology gate owns it); got %v", serr)
	}

	// --- Wiring: commitAndApply rejects a day-2 cluster-id change, promotes nothing. ---
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Commit a clustered active (node 0 / cluster-id 1) to mirror a running
	// clustered node's on-disk state.
	if err := store.SetFromInput("chassis cluster cluster-id 1"); err != nil {
		t.Fatalf("set cluster-id 1: %v", err)
	}
	if err := store.SetFromInput("chassis cluster node 0"); err != nil {
		t.Fatalf("set node 0: %v", err)
	}
	// #6611: an unkeyed chassis cluster is a hard reject on the strict commit
	// path, so the fixture must carry the control-channel PSK to reach the
	// identity preflight this test is about.
	if err := store.SetFromInput("chassis cluster authentication-key test-cluster-psk-6611"); err != nil {
		t.Fatalf("set authentication-key: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit clustered active: %v", err)
	}
	if active := store.ActiveConfig(); !clusterTopologyConfigured(active) ||
		active.Chassis.Cluster.ClusterID != 1 {
		t.Fatalf("precondition: active must be clustered cluster-id 1; got %+v", active)
	}
	// Still in configuration mode — stage a cluster-id CHANGE (1 -> 2) as the
	// candidate. commitAndApply performs the commit; the preflight must reject
	// before promotion.
	if err := store.SetFromInput("chassis cluster cluster-id 2"); err != nil {
		t.Fatalf("set cluster-id 2: %v", err)
	}

	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), cluster: running}
	_, capErr := d.commitAndApply(context.Background(), "change cluster-id", peerSyncNever)
	if capErr == nil || !errors.Is(capErr, errClusterIdentityRequiresRestart) {
		t.Fatalf("commitAndApply of a day-2 cluster-id change must be rejected with the "+
			"identity-restart sentinel; got %v", capErr)
	}
	// The candidate must NOT have been promoted: active still holds cluster-id 1.
	if active := store.ActiveConfig(); !clusterTopologyConfigured(active) ||
		active.Chassis.Cluster.ClusterID != 1 {
		t.Fatalf("a rejected identity change must NOT promote the candidate; "+
			"active cluster-id should still be 1, got %+v", active)
	}
}
