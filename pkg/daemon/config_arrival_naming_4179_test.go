package daemon

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

type namingCall struct {
	nodeID      int
	clusterMode bool
}

// withNamingCallRecorder stubs the positional/device-map naming dispatch and
// records the (nodeID, clusterMode) the positional path is invoked with.
func withNamingCallRecorder(t *testing.T) *[]namingCall {
	t.Helper()
	savedPos := enumerateAndRenameInterfacesFn
	savedMapped := enumerateAndRenameMappedFn
	var calls []namingCall
	enumerateAndRenameInterfacesFn = func(nodeID int, clusterMode bool, _ int, _ bool, _ []string) error {
		calls = append(calls, namingCall{nodeID: nodeID, clusterMode: clusterMode})
		return nil
	}
	enumerateAndRenameMappedFn = func(*config.DeviceMapConfig, *config.Config, map[string]bool) error {
		t.Fatal("device-map branch must not fire for a plain cluster config")
		return nil
	}
	t.Cleanup(func() {
		enumerateAndRenameInterfacesFn = savedPos
		enumerateAndRenameMappedFn = savedMapped
	})
	return &calls
}

func newStoreDaemon(t *testing.T) *Daemon {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	return &Daemon{store: store}
}

func clusterConfigNode1() *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 1}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-7/0/1": {Name: "ge-7/0/1"},
	}
	return cfg
}

// TestConfigArrivalRenamingHANode is the #4179 regression: a config-less HA
// node (emptyHANamingPending set at boot) that receives its first non-empty
// CLUSTER config must re-run startup naming in CLUSTER mode with the node's ID
// (node 1 => FPC 7), so the standalone-named NICs are renamed to em0 +
// ge-7-0-X. Reverting the fix (maybeReapplyConfigArrivalNaming becomes a no-op,
// or the boot flag is never set) makes this RED: naming is never re-run and the
// interfaces keep their standalone boot names.
func TestConfigArrivalRenamingHANode(t *testing.T) {
	calls := withNamingCallRecorder(t)
	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	cfg := clusterConfigNode1()
	if !d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Fatal("expected config-arrival re-naming to run on the first non-empty cluster config")
	}
	if len(*calls) != 1 {
		t.Fatalf("expected exactly one naming re-run, got %d", len(*calls))
	}
	if !(*calls)[0].clusterMode || (*calls)[0].nodeID != 1 {
		t.Fatalf("re-naming must use cluster mode + node 1 (FPC 7), got clusterMode=%v nodeID=%d",
			(*calls)[0].clusterMode, (*calls)[0].nodeID)
	}

	// One-shot: a second apply of the same config must NOT re-name.
	if d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Fatal("config-arrival re-naming must be one-shot; second apply re-ran it")
	}
	if len(*calls) != 1 {
		t.Fatalf("second apply re-ran naming (%d calls); must be one-shot", len(*calls))
	}
}

// TestConfigArrivalRenamingEmptyConfigDoesNotConsumeFlag proves an empty
// config (no interfaces) does not consume the one-shot flag — naming waits for
// the REAL cluster config, mirroring the bootstrap-exit "empty config is not a
// takeover" rule.
func TestConfigArrivalRenamingEmptyConfigDoesNotConsumeFlag(t *testing.T) {
	calls := withNamingCallRecorder(t)
	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	empty := &config.Config{}
	if d.maybeReapplyConfigArrivalNaming(empty) {
		t.Fatal("an empty config must not trigger config-arrival re-naming")
	}
	if len(*calls) != 0 {
		t.Fatalf("empty config must not re-run naming, got %d calls", len(*calls))
	}

	// The flag survived: the real cluster config still triggers naming.
	if !d.maybeReapplyConfigArrivalNaming(clusterConfigNode1()) {
		t.Fatal("the flag must survive an empty config so the real cluster config re-runs naming")
	}
	if len(*calls) != 1 {
		t.Fatalf("cluster config must re-run naming after the empty one, got %d calls", len(*calls))
	}
}

// TestConfigArrivalRenamingSkippedWhenNotPending proves a normal node (flag
// never set — it booted WITH a config) never re-runs naming on a day-2 commit.
func TestConfigArrivalRenamingSkippedWhenNotPending(t *testing.T) {
	calls := withNamingCallRecorder(t)
	d := newStoreDaemon(t) // emptyHANamingPending defaults false

	if d.maybeReapplyConfigArrivalNaming(clusterConfigNode1()) {
		t.Fatal("a node that did not boot config-less must not re-run naming")
	}
	if len(*calls) != 0 {
		t.Fatalf("no naming re-run expected on a normal node, got %d calls", len(*calls))
	}
}
