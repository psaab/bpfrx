package upgrade

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeNodeID makes the runner's configured cluster-identity marker present,
// flipping the test node from STANDALONE to a cluster MEMBER (#5284). The
// runner stats cfg.NodeIDPath at Run() time, so writing it after testEnv is
// seen by a subsequent Run.
func writeNodeID(t *testing.T, cfg Config, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(cfg.NodeIDPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.NodeIDPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestClusterGate_BareCutOnClusteredNodeRefused is the core #5284 invariant:
// a BARE standalone cut (r.Run with no ClusterCoordinated flag) on a node
// that carries /etc/xpf/node-id is REFUSED at the final privileged boundary,
// BEFORE StopUnit — so the local daemon is never stopped and the cluster
// keeps forwarding. We seed a real rollback target (versions/current) so the
// ONLY reason a run can be refused is the cluster gate, not the #1964
// refuse-before-STOP (no-previous) guard — this isolates the new behavior.
//
// RED-on-revert: delete the cluster gate in Runner.Run and this test fails —
// the bare cut proceeds to StopUnit and completes (current -> 2.0.0), so the
// "stop must never be called" and "unit still running" assertions trip.
func TestClusterGate_BareCutOnClusteredNodeRefused(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0") // real rollback target => not the no-prev guard
	writeNodeID(t, cfg, "0\n")             // this node is a cluster member

	err := r.Run(Options{}) // BARE cut, no ClusterCoordinated
	if err == nil {
		t.Fatal("expected the clustered-node cut to be refused, got nil")
	}
	if !strings.Contains(err.Error(), "refuse-standalone-cut-on-clustered-node") {
		t.Fatalf("error is not the #5284 cluster gate: %v", err)
	}
	if !strings.Contains(err.Error(), "--rolling") {
		t.Fatalf("cluster-gate error must direct the operator to the rolling driver: %v", err)
	}

	// StopUnit must NEVER have been called (the whole point: no uncoordinated
	// stop on a clustered node). Assert via the fake unit-stopper call log.
	for _, c := range fs.calls {
		if c == "stop" || c == "start" || c == "dropin" || c == "daemon-reload" {
			t.Errorf("live mutation %q happened despite the clustered-node refusal", c)
		}
	}
	if !fs.unitRunning {
		t.Error("the daemon was stopped despite the clustered-node refusal")
	}
	// The gate fires BEFORE loadJournal, so no journal is ever persisted.
	if _, serr := os.Stat(cfg.JournalPath); !os.IsNotExist(serr) {
		t.Error("a journal was persisted despite the pre-lock clustered-node refusal")
	}
	// current must still point at the seeded prior version (never flipped).
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "1.0.0" {
		t.Errorf("current moved off the seeded prior version: %q", target)
	}
}

// TestClusterGate_StandaloneNodeProceeds is the no-regression case: with NO
// /etc/xpf/node-id (the testEnv default points NodeIDPath at an absent
// tempdir file), the bare standalone cut proceeds exactly as before — the
// unit is stopped and the cut completes.
func TestClusterGate_StandaloneNodeProceeds(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	// No writeNodeID => standalone node.

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("standalone bare cut must proceed unchanged: %v", err)
	}
	sawStop := false
	for _, c := range fs.calls {
		if c == "stop" {
			sawStop = true
		}
	}
	if !sawStop {
		t.Error("standalone cut did not stop the unit — the flow regressed")
	}
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "2.0.0" {
		t.Errorf("standalone cut did not flip to 2.0.0: current=%q", target)
	}
}

// TestClusterGate_RollingDriverNotBlocked is the key correctness point: the
// COORDINATED rolling driver legitimately performs the local cut as part of
// its per-node drain, and MUST NOT be blocked by the #5284 gate even though
// /etc/xpf/node-id is present. runRollingWith invokes the inner cut with
// ClusterCoordinated=true, so the gate distinguishes the bare standalone cut
// from the rolling-driver-invoked local cut. We assert the cut completes (a
// drop-in was written and current advanced) rather than being refused.
func TestClusterGate_RollingDriverNotBlocked(t *testing.T) {
	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)
	seedInitialCurrent(t, r, cfg, "1.0.0")
	writeNodeID(t, cfg, "1\n") // clustered node — the gate would block a BARE cut

	cl := &fakeCluster{peerAlive: true, synced: true, compatible: true, peerReady: true, drainAfter: 2}
	if err := runRollingWith(r, cl, fastRC()); err != nil {
		t.Fatalf("rolling cut on a clustered node must NOT be blocked by the #5284 gate: %v", err)
	}
	if !cl.forced {
		t.Error("ForceSecondary not called — the rolling drain did not run")
	}
	if fs.dropinContent == "" {
		t.Error("no cut happened on the clustered node under the rolling driver (gate wrongly blocked it)")
	}
	target, _ := os.Readlink(filepath.Join(cfg.VersionsDir, "current"))
	if filepath.Base(target) != "2.0.0" {
		t.Errorf("rolling cut did not flip to 2.0.0: current=%q", target)
	}
}
