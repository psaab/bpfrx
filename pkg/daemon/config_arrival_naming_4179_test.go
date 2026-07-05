package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

type namingCall struct {
	nodeID      int
	clusterMode bool
}

// namingStub records positional naming invocations and can inject an error on
// the first N calls (to exercise the #4179 retry-on-failure path).
type namingStub struct {
	calls    []namingCall
	failNext int   // fail the next N calls, then succeed
	failErr  error // error returned while failNext > 0
}

// withNamingStub installs a configurable stub over the positional/device-map
// naming dispatch. The returned *namingStub can be inspected (calls) and armed
// (failNext) by the test.
func withNamingStub(t *testing.T) *namingStub {
	t.Helper()
	savedPos := enumerateAndRenameInterfacesFn
	savedMapped := enumerateAndRenameMappedFn
	st := &namingStub{}
	enumerateAndRenameInterfacesFn = func(nodeID int, clusterMode bool, _ int, _ bool, _ []string) error {
		st.calls = append(st.calls, namingCall{nodeID: nodeID, clusterMode: clusterMode})
		if st.failNext > 0 {
			st.failNext--
			return st.failErr
		}
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
	return st
}

func newStoreDaemon(t *testing.T) *Daemon {
	t.Helper()
	// Pin the #1922 lifeline record to a non-existent temp path so
	// resolveProtectedInterfaces (reached via applyStartupNamingForConfig)
	// does not read the host's /etc/xpf lifeline record — keeps the test
	// hermetic regardless of host state.
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = "" })

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
	st := withNamingStub(t)
	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	cfg := clusterConfigNode1()
	if !d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Fatal("expected config-arrival re-naming to run on the first non-empty cluster config")
	}
	if len(st.calls) != 1 {
		t.Fatalf("expected exactly one naming re-run, got %d", len(st.calls))
	}
	if !st.calls[0].clusterMode || st.calls[0].nodeID != 1 {
		t.Fatalf("re-naming must use cluster mode + node 1 (FPC 7), got clusterMode=%v nodeID=%d",
			st.calls[0].clusterMode, st.calls[0].nodeID)
	}

	// One-shot: a second apply of the same config must NOT re-name.
	if d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Fatal("config-arrival re-naming must be one-shot; second apply re-ran it")
	}
	if len(st.calls) != 1 {
		t.Fatalf("second apply re-ran naming (%d calls); must be one-shot", len(st.calls))
	}
}

// TestConfigArrivalRenamingRetriesOnFailure is the Copilot-caught robustness
// bug (#4182 review): the flag must be consumed only on SUCCESS. A transient
// naming failure (NIC enumeration / netlink error) on the first config apply
// must LEAVE the flag set so the NEXT apply retries — otherwise a config-less
// HA node is stranded on standalone names forever after one blip. Reverting to
// consume-the-flag-first (CompareAndSwap before applyStartupNamingForConfig)
// makes this RED: the second apply never re-runs naming.
func TestConfigArrivalRenamingRetriesOnFailure(t *testing.T) {
	st := withNamingStub(t)
	st.failNext = 1
	st.failErr = errors.New("transient NIC enumeration failure")

	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	cfg := clusterConfigNode1()

	// First apply: naming is attempted but errors → returns false, flag STAYS.
	if d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Fatal("a failed naming attempt must not report success")
	}
	if len(st.calls) != 1 {
		t.Fatalf("first apply should have attempted naming once, got %d", len(st.calls))
	}
	if !d.emptyHANamingPending.Load() {
		t.Fatal("the flag must STAY SET after a failed naming attempt so the next apply retries")
	}

	// Second apply: the stub now succeeds → naming re-runs and the flag is
	// consumed.
	if !d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Fatal("the second apply must retry naming after the first failed")
	}
	if len(st.calls) != 2 {
		t.Fatalf("second apply should have retried naming, got %d total calls", len(st.calls))
	}
	if d.emptyHANamingPending.Load() {
		t.Fatal("the flag must be consumed after the retry succeeded")
	}

	// Third apply: one-shot — no further re-naming.
	if d.maybeReapplyConfigArrivalNaming(cfg) {
		t.Fatal("naming must not re-run after a successful retry consumed the flag")
	}
	if len(st.calls) != 2 {
		t.Fatalf("no further naming expected after success, got %d calls", len(st.calls))
	}
}

// TestConfigArrivalRenamingEmptyConfigDoesNotConsumeFlag proves an empty
// config (no interfaces) does not consume the one-shot flag — naming waits for
// the REAL cluster config, mirroring the bootstrap-exit "empty config is not a
// takeover" rule.
func TestConfigArrivalRenamingEmptyConfigDoesNotConsumeFlag(t *testing.T) {
	st := withNamingStub(t)
	d := newStoreDaemon(t)
	d.emptyHANamingPending.Store(true)

	empty := &config.Config{}
	if d.maybeReapplyConfigArrivalNaming(empty) {
		t.Fatal("an empty config must not trigger config-arrival re-naming")
	}
	if len(st.calls) != 0 {
		t.Fatalf("empty config must not re-run naming, got %d calls", len(st.calls))
	}

	// The flag survived: the real cluster config still triggers naming.
	if !d.maybeReapplyConfigArrivalNaming(clusterConfigNode1()) {
		t.Fatal("the flag must survive an empty config so the real cluster config re-runs naming")
	}
	if len(st.calls) != 1 {
		t.Fatalf("cluster config must re-run naming after the empty one, got %d calls", len(st.calls))
	}
}

// TestConfigArrivalRenamingSkippedWhenNotPending proves a normal node (flag
// never set — it booted WITH a config) never re-runs naming on a day-2 commit.
func TestConfigArrivalRenamingSkippedWhenNotPending(t *testing.T) {
	st := withNamingStub(t)
	d := newStoreDaemon(t) // emptyHANamingPending defaults false

	if d.maybeReapplyConfigArrivalNaming(clusterConfigNode1()) {
		t.Fatal("a node that did not boot config-less must not re-run naming")
	}
	if len(st.calls) != 0 {
		t.Fatalf("no naming re-run expected on a normal node, got %d calls", len(st.calls))
	}
}
