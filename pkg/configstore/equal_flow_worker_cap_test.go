package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// equalFlowOverCapSets is a config that enables CoS equal-flow-enforcement
// on more than config.MaxEqualFlowWorkers workers. The strict commit path
// hard-rejects it (#1733); the tolerant Load / SyncApply paths must accept
// it with a warning so an upgraded node boots and HA sync converges.
func equalFlowOverCapSets() []string {
	return []string{
		"set system dataplane-type userspace",
		"set system dataplane workers 33", // > MaxEqualFlowWorkers (32)
		"set class-of-service schedulers ef-sched transmit-rate 10m exact",
		"set class-of-service schedulers ef-sched equal-flow-enforcement",
	}
}

func hasWorkerCapWarning(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "equal-flow-enforcement is unsupported") {
			return true
		}
	}
	return false
}

// TestStoreLoad_ToleratesEqualFlowOverWorkerCap is the round-1 MAJOR
// regression gate for the Load path: a persisted >cap + equal-flow config
// (committed before the #1733 gate existed) must NOT blackout-boot. Load
// must succeed, the active config must be present, and a worker-cap
// warning must be surfaced.
func TestStoreLoad_ToleratesEqualFlowOverWorkerCap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := New(filepath.Join(dir, "xpf.conf"))

	tree := mustParseTree(t, equalFlowOverCapSets()...)
	if err := store.db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive (simulating pre-#1733 persisted config): %v", err)
	}

	if err := store.Load(); err != nil {
		t.Fatalf("Load blacked out on a tolerated legacy config: %v", err)
	}
	active := store.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig is nil after Load — daemon would boot blind")
	}
	if !hasWorkerCapWarning(active) {
		t.Fatalf("Load did not surface a worker-cap warning: %v", active.Warnings)
	}
	// Warning-only downgrade: the equal-flow leaf is preserved (the
	// runtime fail-opens it, exactly as before this gate).
	sched := active.ClassOfService.Schedulers["ef-sched"]
	if sched == nil || !sched.EqualFlowEnforcement {
		t.Fatal("Load must preserve equal-flow-enforcement (warning-only, no mutation)")
	}
}

// TestStoreLoad_NoWarnAtWorkerCapBoundary confirms a config exactly at the
// cap loads cleanly with no worker-cap warning.
func TestStoreLoad_NoWarnAtWorkerCapBoundary(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := New(filepath.Join(dir, "xpf.conf"))

	tree := mustParseTree(t,
		"set system dataplane-type userspace",
		"set system dataplane workers 32", // == MaxEqualFlowWorkers
		"set class-of-service schedulers ef-sched transmit-rate 10m exact",
		"set class-of-service schedulers ef-sched equal-flow-enforcement",
	)
	if err := store.db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load at the worker cap returned error: %v", err)
	}
	if hasWorkerCapWarning(store.ActiveConfig()) {
		t.Fatalf("unexpected worker-cap warning at the boundary: %v",
			store.ActiveConfig().Warnings)
	}
}

// TestStoreSyncApply_ToleratesEqualFlowOverWorkerCap is the round-1 MAJOR
// regression gate for the HA peer-sync path: an upgraded standby
// receiving a >cap + equal-flow config from an un-upgraded primary must
// accept it (with a warning) rather than alarm-loop sync.
func TestStoreSyncApply_ToleratesEqualFlowOverWorkerCap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := New(filepath.Join(dir, "xpf.conf"))

	content := mustParseTree(t, equalFlowOverCapSets()...).Format()

	compiled, err := store.SyncApply(content, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected a tolerated peer config (HA sync would alarm-loop): %v", err)
	}
	if !hasWorkerCapWarning(compiled) {
		t.Fatalf("SyncApply did not surface a worker-cap warning: %v", compiled.Warnings)
	}
	sched := compiled.ClassOfService.Schedulers["ef-sched"]
	if sched == nil || !sched.EqualFlowEnforcement {
		t.Fatal("SyncApply must preserve equal-flow-enforcement (warning-only, no mutation)")
	}
}

// TestCommitCheck_RejectsEqualFlowOverWorkerCap is the store-level
// strict-commit regression gate: an operator candidate edit that puts
// workers > MaxEqualFlowWorkers with equal-flow-enforcement must be
// hard-rejected by CommitCheck AND Commit (they use the strict
// compileTree, not the lenient load/sync path). This pins the asymmetry:
// load/sync tolerate (above), but a deliberate operator commit does not.
func TestCommitCheck_RejectsEqualFlowOverWorkerCap(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"system dataplane-type userspace",
		"system dataplane workers 33",
		"class-of-service schedulers ef-sched transmit-rate 10m exact",
		"class-of-service schedulers ef-sched equal-flow-enforcement",
	} {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("expected CommitCheck to reject >cap equal-flow config, got nil")
	}
	if !strings.Contains(err.Error(), "equal-flow-enforcement is unsupported") {
		t.Fatalf("CommitCheck error should reference the worker cap: %v", err)
	}
	// Commit must refuse the same way (also strict).
	if _, err := s.Commit(); err == nil {
		t.Fatal("expected Commit to reject >cap equal-flow config, got nil")
	}
}

// TestCommitCheck_AcceptsEqualFlowAtWorkerCap is the boundary companion:
// exactly MaxEqualFlowWorkers workers + equal-flow commits cleanly.
func TestCommitCheck_AcceptsEqualFlowAtWorkerCap(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"system dataplane-type userspace",
		"system dataplane workers 32",
		"class-of-service schedulers ef-sched transmit-rate 10m exact",
		"class-of-service schedulers ef-sched equal-flow-enforcement",
	} {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("CommitCheck at the worker cap returned error: %v", err)
	}
}
