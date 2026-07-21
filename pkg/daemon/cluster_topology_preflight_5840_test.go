package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sync/semaphore"
)

func standaloneCfg() *config.Config {
	cfg := &config.Config{}
	cfg.System.HostName = "standalone-node"
	return cfg
}

func clusterCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1, NodeID: 0}
	return cfg
}

// TestClusterTopologyDay2TransitionRejected is the #5840 fail-on-revert gate.
//
// The chassis-cluster runtime is constructed only at boot (daemon_run.go
// initManagers + startClusterComms). A DAY-2 commit that flips a running
// daemon between standalone and cluster mode cannot (de)construct that
// boot-only runtime, and silently accepting it publishes clustered dataplane
// semantics (clusterHA=true) with no election/watchdog runtime — a persistent
// transit outage until restart, plus a data race on the bare d.cluster pointer.
// clusterTopologyCommitPreflight must REJECT the transition BEFORE store
// promotion / any dataplane mutation, in both directions, while leaving an
// intra-mode edit untouched.
//
// Reverting the fix (clusterTopologyCommitPreflight returns nil) makes the
// FIRST assertion below RED as an assertion — exactly one test binds the
// production reject line. The end-to-end commitAndApply leg then proves the
// preflight is wired into the commit path and that a rejected transition writes
// NO d.cluster and mutates NO dataplane.
func TestClusterTopologyDay2TransitionRejected(t *testing.T) {
	// --- Direct preflight: the precise binding (both transition directions). ---
	// standalone -> cluster: the #5840 bug.
	err := clusterTopologyCommitPreflight(standaloneCfg(), clusterCfg())
	if err == nil {
		t.Fatal("standalone->cluster day-2 transition must be REJECTED (adding " +
			"chassis cluster cannot form the cluster without a restart)")
	}
	if !errors.Is(err, errClusterTopologyRequiresRestart) {
		t.Fatalf("rejection must wrap the restart-required sentinel; got %v", err)
	}
	if !strings.Contains(err.Error(), "chassis cluster") ||
		!strings.Contains(err.Error(), "restart") {
		t.Fatalf("rejection must carry an actionable operator diagnostic; got %q", err.Error())
	}

	// cluster -> standalone: the reverse teardown, also unsafe live.
	if rerr := clusterTopologyCommitPreflight(clusterCfg(), standaloneCfg()); rerr == nil ||
		!errors.Is(rerr, errClusterTopologyRequiresRestart) {
		t.Fatalf("cluster->standalone day-2 transition must be REJECTED with the "+
			"restart-required sentinel; got %v", rerr)
	}

	// --- Controls: an intra-mode edit (no topology change) is ACCEPTED. ---
	if aerr := clusterTopologyCommitPreflight(standaloneCfg(), standaloneCfg()); aerr != nil {
		t.Fatalf("standalone->standalone commit must be accepted; got %v", aerr)
	}
	if aerr := clusterTopologyCommitPreflight(clusterCfg(), clusterCfg()); aerr != nil {
		t.Fatalf("cluster->cluster commit must be accepted; got %v", aerr)
	}
	// Initial config load (nil old): the boot path owns construction — accepted.
	if aerr := clusterTopologyCommitPreflight(nil, clusterCfg()); aerr != nil {
		t.Fatalf("initial (nil-old) config load must be accepted; got %v", aerr)
	}

	// --- Wiring: commitAndApply rejects the transition with no runtime write. ---
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure (standalone): %v", err)
	}
	if err := store.SetFromInput("system host-name standalone-node"); err != nil {
		t.Fatalf("set standalone host-name: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit standalone active: %v", err)
	}
	// Still in configuration mode after the commit — seed a chassis-cluster
	// CANDIDATE (not committed; commitAndApply performs the commit).
	if err := store.SetFromInput("chassis cluster cluster-id 1"); err != nil {
		t.Fatalf("set cluster-id: %v", err)
	}
	if err := store.SetFromInput("chassis cluster node 0"); err != nil {
		t.Fatalf("set node: %v", err)
	}

	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	_, cerr := d.commitAndApply(context.Background(), "add chassis cluster", false)
	if cerr == nil || !errors.Is(cerr, errClusterTopologyRequiresRestart) {
		t.Fatalf("commitAndApply of a standalone->cluster transition must be "+
			"rejected with the restart-required sentinel; got %v", cerr)
	}
	if d.cluster != nil {
		t.Fatal("a rejected transition must NOT construct the cluster runtime " +
			"(d.cluster must stay nil)")
	}
	// The candidate must NOT have been promoted: active is still standalone.
	if active := store.ActiveConfig(); clusterTopologyConfigured(active) {
		t.Fatal("a rejected transition must NOT promote the cluster candidate to active")
	}
}
