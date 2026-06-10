package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #1319 PR 2 — boot safety for the typed-leaf gate.
//
// The SchemaValidate gate is strict ONLY on the operator-driven commit /
// commit-check path. A typed-leaf violation in an already-persisted config
// (written by an older binary, before the leaf was typed or its range
// tightened) must NOT fail Store.Load — a node with a bad stored value
// would otherwise boot with no active config (operational blackout).
// Same for Store.SyncApply (HA config sync from a possibly-un-upgraded
// primary must not alarm-loop). compileTreeLenient downgrades the gate to
// a warning on exactly those two paths.

// writeStoredConfig persists a flat-set-built tree directly through the
// DB, bypassing commit validation — simulating a config persisted by a
// pre-gate binary.
func writeStoredConfig(t *testing.T, cfgPath string, lines ...string) {
	t.Helper()
	writer := New(cfgPath)
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	if err := writer.db.WriteActive(tree); err != nil {
		t.Fatalf("db.WriteActive: %v", err)
	}
}

// A stored typed-leaf GARBAGE value (the PR-1 schedulers leaves) must not
// fail boot. Before #1319 PR 2 this returned "compile config: ... invalid
// value \"asd\"" from Load, leaving the daemon with no active config.
func TestLoad_ToleratesStoredGarbageTypedLeaf(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set class-of-service schedulers be transmit-rate asd")

	s := New(cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate stored typed-leaf garbage, got: %v", err)
	}
	if s.ActiveConfig() == nil {
		t.Fatal("ActiveConfig() is nil after tolerated Load")
	}

	// The next STRICT operator commit must still reject the stale value.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must stay strict after a tolerated Load, got nil")
	}
	if !strings.Contains(err.Error(), "transmit-rate") {
		t.Fatalf("CommitCheck error should reference transmit-rate: %v", err)
	}
}

// HA config sync from a primary carrying a typed-leaf violation must not
// alarm-loop the standby: SyncApply uses the same lenient path as Load.
func TestSyncApply_ToleratesTypedLeafViolation(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`class-of-service {
    schedulers {
        be {
            transmit-rate asd;
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply must tolerate a typed-leaf violation, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned nil config on tolerated violation")
	}
}

// #1319 PR 2 — an OUT-OF-RANGE chassis-cluster value in a stored config
// (legal when persisted; the range was typed later) must not fail boot.
// The compiler keeps accepting it verbatim, so running behavior is
// preserved; the warning surfaces the condition and the next strict
// commit rejects it.
func TestLoad_ToleratesStoredOutOfRangeChassisLeaf(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath,
		"set chassis cluster cluster-id 1",
		"set chassis cluster heartbeat-interval 99999")

	s := New(cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load() must tolerate stored out-of-range heartbeat-interval, got: %v", err)
	}
	active := s.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig() is nil after tolerated Load")
	}
	// Verbatim compile — running behavior preserved, no silent rewrite.
	if active.Chassis.Cluster == nil || active.Chassis.Cluster.HeartbeatInterval != 99999 {
		t.Fatalf("stored out-of-range value must compile verbatim, got %+v", active.Chassis.Cluster)
	}

	// The next STRICT operator commit rejects the stale value.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("CommitCheck must reject the out-of-range stored value, got nil")
	}
	if !strings.Contains(err.Error(), "heartbeat-interval") {
		t.Fatalf("CommitCheck error should reference heartbeat-interval: %v", err)
	}
}

// Strict-path e2e for a chassis typed leaf: CommitCheck and Commit reject
// an out-of-range value entered by the operator.
func TestCommitCheck_RejectsOutOfRangeChassisLeaf(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("chassis cluster redundancy-group 1 node 0 priority 255"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject priority 255 (VRRP owner-reserved), got nil")
	}
	if !strings.Contains(err.Error(), "priority") {
		t.Fatalf("CommitCheck error should reference priority: %v", err)
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("expected Commit to reject priority 255, got nil")
	}
}
