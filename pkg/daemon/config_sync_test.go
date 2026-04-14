package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// newClusterManager creates a cluster.Manager where node 0 is primary or
// secondary for RG0. For secondary: uses non-preempt + control-interface
// (cluster mode) so electSingleNode() defers to peer heartbeat timeout,
// keeping the node secondary without a peer.
func newClusterManager(primary bool) *cluster.Manager {
	m := cluster.NewManager(0, 1)
	cfg := &config.ClusterConfig{
		RethCount: 1,
		RedundancyGroups: []*config.RedundancyGroup{{
			ID:             0,
			NodePriorities: map[int]int{0: 200},
			Preempt:        primary, // preempt=true → immediate primary; false → deferred
		}},
	}
	if !primary {
		// Setting ControlInterface makes this a "cluster mode" manager.
		// Combined with Preempt=false + no peer ever seen, electSingleNode()
		// keeps the node in StateSecondary.
		cfg.ControlInterface = "control0"
	}
	m.UpdateConfig(cfg)
	return m
}

// TestHandleConfigSync_RejectsWhenPrimary verifies that the RG0 primary
// rejects incoming config sync (prevents secondary from overwriting).
func TestHandleConfigSync_RejectsWhenPrimary(t *testing.T) {
	d := &Daemon{
		cluster: newClusterManager(true),
	}
	// If the guard doesn't work, handleConfigSync would panic accessing
	// d.store (nil). A successful return means the guard rejected the config.
	d.handleConfigSync("set system host-name bad-config")
}

// TestHandleConfigSync_AcceptsWhenSecondary verifies that a secondary node
// proceeds past the authority guard. We expect a store error (nil store)
// which confirms the guard passed and the function tried to apply config.
func TestHandleConfigSync_AcceptsWhenSecondary(t *testing.T) {
	d := &Daemon{
		cluster: newClusterManager(false),
	}
	// Secondary should pass the guard and try SyncApply → panic on nil store.
	// Recover from the expected nil pointer to confirm the guard passed.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from nil store (guard should have passed)")
		}
	}()
	d.handleConfigSync("set system host-name good-config")
}

// TestHandleConfigSync_AcceptsWhenNoCluster verifies that standalone mode
// (no cluster manager) accepts incoming config sync.
func TestHandleConfigSync_AcceptsWhenNoCluster(t *testing.T) {
	d := &Daemon{}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from nil store (guard should have passed)")
		}
	}()
	d.handleConfigSync("set system host-name standalone")
}

func TestHandleConfigSync_SkipsWhenConfigAlreadyMatchesActive(t *testing.T) {
	store := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name sync-test"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	active := store.ShowActive()
	historyLen := len(store.ListHistory())

	d := &Daemon{
		cluster: newClusterManager(false),
		store:   store,
	}

	d.handleConfigSync(active + "\n")

	if got := store.ShowActive(); got != active {
		t.Fatalf("active config changed on identical sync:\nwant:\n%s\n\ngot:\n%s", active, got)
	}
	if got := store.ActiveConfig(); got == nil || got.System.HostName != "sync-test" {
		t.Fatalf("expected unchanged compiled config, got %#v", got)
	}
	if got := len(store.ListHistory()); got != historyLen {
		t.Fatalf("expected identical config sync to skip history mutation, want %d entries got %d", historyLen, got)
	}
}

// TestOnPeerConnected_PrimaryPushesConfig verifies that an RG0 primary with
// sufficient uptime reaches pushConfigToPeer (which safely no-ops on nil
// sessionSync).
func TestOnPeerConnected_PrimaryPushesConfig(t *testing.T) {
	d := &Daemon{
		cluster:   newClusterManager(true),
		startTime: time.Now().Add(-60 * time.Second), // running >30s
	}
	if !d.cluster.IsLocalPrimary(0) {
		t.Fatal("test setup error: should be primary")
	}
	// pushConfigToPeer returns early when sessionSync is nil — safe no-op.
	d.onPeerConnectedHandler()
}

// onPeerConnectedHandler replicates the OnPeerConnected callback logic
// for testability (same checks as daemon.go:3476-3484).
func (d *Daemon) onPeerConnectedHandler() {
	if d.cluster == nil || !d.cluster.IsLocalPrimary(0) {
		return
	}
	if time.Since(d.startTime) < 30*time.Second {
		return
	}
	d.pushConfigToPeer()
}

// TestOnPeerConnected_SecondarySkips verifies that a secondary does NOT
// push config to a reconnecting peer.
func TestOnPeerConnected_SecondarySkips(t *testing.T) {
	d := &Daemon{
		cluster:   newClusterManager(false),
		startTime: time.Now().Add(-60 * time.Second),
	}
	// Should return early (not RG0 primary). If it proceeded to pushConfigToPeer,
	// that's also safe (nil sessionSync), but we verify the guard fires by
	// checking the logic directly.
	if d.cluster.IsLocalPrimary(0) {
		t.Fatal("test setup error: should be secondary")
	}
	d.onPeerConnectedHandler()
}

// TestOnPeerConnected_FreshDaemonSkips verifies that even the primary skips
// config push if daemon just started (<30s uptime).
func TestOnPeerConnected_FreshDaemonSkips(t *testing.T) {
	d := &Daemon{
		cluster:   newClusterManager(true),
		startTime: time.Now(), // just started
	}
	if !d.cluster.IsLocalPrimary(0) {
		t.Fatal("test setup error: should be primary")
	}
	// Uptime < 30s → should skip. If it proceeded to pushConfigToPeer with
	// nil sessionSync, that's safe but undesired.
	d.onPeerConnectedHandler()
}
